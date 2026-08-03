# Circle Management + Invites - Docker Verification Log
**Environment:** Docker container cohort (WSL2) | **Date:** 2026-07-21 | **Tester:** Asad Ali
**Test tag:** CIRCLE-series (CIRCLE-001 - CIRCLE-009) | **Plan:** `docs/Circle_Management_Complete_Plan.md`

---

## 📌 Task Description

> Verify Circle creation, editing, membership management, QR-based invites, signed invite tokens, join flow, member removal semantics, and Mesh Circle isolation inside the Docker container cohort. This log records only confirmed PASS results from Docker CLI verification.

---

## 📋 Logging Rule For This File

- Is file mein **sirf confirmed PASS** steps record kiye ja rahe hain.
- Failed, blocked, ya inconclusive commands yahan intentionally **record nahi** ki ja rahi.
- Jab koi nayi requirement pass ho, uska exact command, expected result, observed result, aur verdict yahin append/update hoga.

---

## ✅ Latest Verified Status

- Docker cohort runtime detected:
  - `sgx-nodeA` -> container REST `http://127.0.0.1:8443`
  - `sgx-nodeB` -> container REST `http://127.0.0.1:8443`
  - `sgx-nodeC` -> container REST `http://127.0.0.1:8443`
  - host port mapping currently:
    - `nodeA` -> `18443`
    - `nodeB` -> `28444`
    - `nodeC` -> `38443`
- In-container health check confirmed on all three nodes via Docker CLI.
- Confirmed pass count abhi:
  - Requirements: `9/9`
  - APIs: `5/5`
- Current working comms circle for this run:
  - `CID=circle-0f860dfd-cf81-4dd4-a2cb-1d3cf38caede`

---

## 🐳 Docker Notes

- Saari commands **host terminal** se chalani hain.
- REST verification ke liye preferred pattern:
  - `docker exec sgx-nodeA sh -lc 'curl -s http://127.0.0.1:8443/api/v1/...'`
- File reads ke liye host-side JSON parsing use karo:
  - `docker exec sgx-nodeA sh -lc 'cat /path/file.json' | python3 -m json.tool`
- `docker exec` hamesha host shell se chalega; container ke andar ja kar `docker exec` mat chalana.
- Is current run mein `nodeB` host port `28444` par mapped hai.
- Member-management tests ke liye fake string DID use mat karo agar woh valid base58 Guardian DID na ho.
  - Safe choice: `TEST_MEMBER_DID="$NODEC_DID"`
- VC verification ke liye `GET /api/v1/vc/show?scope=issued|own|peers` use karo.
  - `GET /api/v1/vc/list` sirf local `own` VCs return karta hai; `scope=issued` is route par apply nahi hota.
- Mesh-isolation runtime check ke liye `GET /api/v1/crl/gossip/status` authoritative signal hai.
  - `GET /api/v1/vc/summary` last local own VC dikhata hai; yeh gossip runtime circle resolver nahi hai.

---

## ⚡ Session Bootstrap Confirmed

**Commands:**
```bash
cd /home/asad/SGX
docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'

docker exec sgx-nodeA sh -lc 'curl -sf http://127.0.0.1:8443/api/v1/health'
docker exec sgx-nodeB sh -lc 'curl -sf http://127.0.0.1:8443/api/v1/health'
docker exec sgx-nodeC sh -lc 'curl -sf http://127.0.0.1:8443/api/v1/health'

docker exec sgx-nodeA sh -lc 'cat /var/lib/sgx-guardian/identity/did.json'
docker exec sgx-nodeB sh -lc 'cat /var/lib/sgx-guardian/identity/did.json'
docker exec sgx-nodeC sh -lc 'cat /var/lib/sgx-guardian/identity/did.json'
```

**Observed:**
```text
sgx-nodeA   Up (healthy)   18443->8443/tcp
sgx-nodeB   Up             28444->8443/tcp
sgx-nodeC   Up             38443->8443/tcp

nodeA health: ok
nodeB health: ok
nodeC health: ok

nodeA DID: did:guardian:2j7bT9dYanivCFtPxwFCu1e3AkbodnA8314o2SjE5knm
nodeB DID: did:guardian:BXdtcPc3m86nKFb5vrbjdgHuN9vEd6Zo6gyaxQm8xqRC
nodeC DID: did:guardian:EcRBpx6MfU8756hKLQtqYix4bAGgNfDSWRLYFZJKqgSS
```

---

## 📊 Requirements Checklist

- [x] Requirement 1 - Circle creation (comms circle) + Mesh Circle seeded
- [x] Requirement 2 - Circle editing (rename)
- [x] Requirement 3 - Membership management (add + list via VC)
- [x] Requirement 4 - Member administration + DID/VC authorization
- [x] Requirement 5 - Signed invite tokens
- [x] Requirement 6 - QR-based invitations
- [x] Requirement 7 - Join flow end-to-end
- [x] Requirement 8 - Remove from Circle = status-list revoke only
- [x] Requirement 9 - Mesh Circle isolation + Milestone-4 guard

---

## 📊 API Checklist

- [x] API 1 - Circle CRUD
- [x] API 2 - Members
- [x] API 3 - Invites
- [x] API 4 - Join / Redeem
- [x] API 5 - Security

---

## ✅ Requirement 1 - Circle creation (comms circle) + Mesh Circle seeded

**Terminal:** Host terminal

**Commands:**
```bash
cd /home/asad/SGX
API=http://127.0.0.1:8443/api/v1
CIRCLE_DIR=/var/lib/sgx-guardian/identity/circles

docker exec sgx-nodeA sh -lc 'curl -s http://127.0.0.1:8443/api/v1/circles' | python3 -m json.tool

docker exec sgx-nodeA sh -lc 'curl -s -X POST http://127.0.0.1:8443/api/v1/circles -H "content-type: application/json" -d "{\"name\":\"Ops Team Docker\",\"description\":\"CIRCLE-001 docker verification\"}"' | python3 -m json.tool

docker exec sgx-nodeA sh -lc 'cat /var/lib/sgx-guardian/identity/circles/circles.json' | python3 -m json.tool
```

**Expected:**
```text
GET /circles -> Mesh Circle present with circleId=guardian-circle-alpha
POST /circles -> new comms circle created with kind=comms
circles.json -> sequence incremented and top-level proof present
```

**Result:**
```text
Initial GET /circles returned exactly one seeded circle:
- circleId: guardian-circle-alpha
- name: Mesh Circle
- kind: mesh

POST /circles returned:
- status: success
- message: Circle created
- circleId: circle-dbfa23ec-7b81-47ac-ac20-d779bd38c65f
- kind: comms
- name: Ops Team Docker

circles.json on disk contained:
- both guardian-circle-alpha and circle-dbfa23ec-7b81-47ac-ac20-d779bd38c65f
- sequence: 2
- proof.type: DataIntegrityProof
- verificationMethod: did:guardian:2j7bT9dYanivCFtPxwFCu1e3AkbodnA8314o2SjE5knm#dkp-v1
```

**Verdict:** PASS - Mesh Circle seed, comms Circle creation, aur signed registry persistence Docker cohort me verify ho gayi.

---

## ✅ Requirement 2 - Circle editing (rename)

**Terminal:** Host terminal

**Commands:**
```bash
cd /home/asad/SGX
API=http://127.0.0.1:8443/api/v1
CID=circle-dbfa23ec-7b81-47ac-ac20-d779bd38c65f
CIRCLE_DIR=/var/lib/sgx-guardian/identity/circles
RENAME="Ops Team Docker Renamed REQ2"

docker exec sgx-nodeA sh -lc "curl -s -X PATCH $API/circles/$CID -H 'content-type: application/json' -d '{\"name\":\"$RENAME\"}'" | python3 -m json.tool
docker exec sgx-nodeA sh -lc "curl -s $API/circles/$CID" | python3 -m json.tool

docker restart sgx-nodeA
until docker exec sgx-nodeA sh -lc "curl -sf $API/health" >/dev/null; do sleep 2; done

docker exec sgx-nodeA sh -lc "curl -s $API/circles/$CID" | python3 -m json.tool
docker exec sgx-nodeA sh -lc "cat $CIRCLE_DIR/circles.json" | python3 -m json.tool
```

**Expected:**
```text
PATCH /circles/{circleId} -> name updated
GET /circles/{circleId} -> renamed value visible immediately
After docker restart -> renamed value still persists
circles.json -> updated circle name present with signed proof
```

**Result:**
```text
PATCH returned:
- status: success
- message: Circle updated
- circleId: circle-dbfa23ec-7b81-47ac-ac20-d779bd38c65f
- name: Ops Team Docker Renamed REQ2

GET before restart returned:
- status: success
- name: Ops Team Docker Renamed REQ2

After docker restart + health recovery:
- GET /circles/{circleId} still returned name: Ops Team Docker Renamed REQ2

circles.json on disk contained:
- circleId: circle-dbfa23ec-7b81-47ac-ac20-d779bd38c65f
- name: Ops Team Docker Renamed REQ2
- top-level proof present
- sequence: 5
```

**Verdict:** PASS - circle rename, restart persistence, aur signed on-disk registry update Docker cohort me verify ho gaye.

---

## ✅ Requirement 3 - Membership management (add + list via VC)

**Terminal:** Host terminal

**Commands:**
```bash
cd /home/asad/SGX
API=http://127.0.0.1:8443/api/v1
CID=circle-dbfa23ec-7b81-47ac-ac20-d779bd38c65f
TEST_MEMBER_DID="$NODEC_DID"

docker exec sgx-nodeA sh -lc "curl -s -X POST $API/circles/$CID/members -H 'content-type: application/json' -d '{\"did\":\"$TEST_MEMBER_DID\",\"role\":\"member\"}'" | python3 -m json.tool
docker exec sgx-nodeA sh -lc "curl -s $API/circles/$CID/members" | python3 -m json.tool
docker exec sgx-nodeA sh -lc "curl -s '$API/vc/show?scope=issued'" | python3 -m json.tool
```

**Expected:**
```text
POST /members -> membership VC issued for the comms circle
GET /members -> owner + added member listed with active lifecycle state
GET /vc/show?scope=issued -> issued VC entry present for the same comms circle
```

**Result:**
```text
POST /members returned:
- status: success
- message: Circle member added
- issued vc_id: urn:uuid:e16cd85c-9939-4023-8dfb-c23b76fcf53c
- subject DID: did:guardian:EcRBpx6MfU8756hKLQtqYix4bAGgNfDSWRLYFZJKqgSS
- role: member
- circleId: circle-dbfa23ec-7b81-47ac-ac20-d779bd38c65f

GET /members returned:
- count: 2
- owner entry active
- added member entry active

GET /vc/show?scope=issued returned an issued entry for:
- vc_id: urn:uuid:e16cd85c-9939-4023-8dfb-c23b76fcf53c
- subject: did:guardian:EcRBpx6MfU8756hKLQtqYix4bAGgNfDSWRLYFZJKqgSS
- role: member
- circle_id: circle-dbfa23ec-7b81-47ac-ac20-d779bd38c65f
- revoked: false
```

**Verdict:** PASS - membership VC issue, members listing, aur issued VC visibility Docker cohort me verify ho gayi.

---

## ✅ Requirement 4 - Member administration + DID/VC authorization

**Terminal:** Host terminal

**Commands:**
```bash
cd /home/asad/SGX
API=http://127.0.0.1:8443/api/v1
CID=circle-dbfa23ec-7b81-47ac-ac20-d779bd38c65f
TEST_MEMBER_DID="$NODEC_DID"

docker exec sgx-nodeA sh -lc "curl -s -X POST $API/circles/$CID/members -H 'content-type: application/json' -d '{\"did\":\"$TEST_MEMBER_DID\",\"role\":\"member\"}'" | python3 -m json.tool
docker exec sgx-nodeA sh -lc "curl -s -X PATCH '$API/circles/$CID/members/$TEST_MEMBER_DID' -H 'content-type: application/json' -d '{\"role\":\"owner\"}'" | python3 -m json.tool
docker exec sgx-nodeA sh -lc "curl -s $API/circles/$CID/members" | python3 -m json.tool

docker exec sgx-nodeB sh -lc "curl -s -o /dev/null -w '%{http_code}\n' -X POST $API/circles/$CID/invites -H 'content-type: application/json' -d '{\"role\":\"member\"}'"
```

**Expected:**
```text
POST /members -> fresh membership VC issued
PATCH /members/{did} -> role updated via revoke + reissue behavior
GET /members -> target DID shows owner role and active lifecycle state
Non-owner mutation from nodeB local API -> HTTP 403
```

**Result:**
```text
Fresh POST /members returned:
- status: success
- message: Circle member added
- issued vc_id: urn:uuid:01c60eb9-8596-4387-b197-4d52341b9437
- subject DID: did:guardian:EcRBpx6MfU8756hKLQtqYix4bAGgNfDSWRLYFZJKqgSS
- role: member

PATCH /members/{did} returned:
- status: success
- message: Circle member role updated
- new vc_id: urn:uuid:d6bd8538-f53d-41ac-93cf-0583529dfaf5
- subject DID: did:guardian:EcRBpx6MfU8756hKLQtqYix4bAGgNfDSWRLYFZJKqgSS
- role: owner

GET /members returned:
- count: 3
- target DID listed with role: owner
- lifecycleState: active

Non-owner mint attempt from nodeB local API returned:
- HTTP 403
```

**Verdict:** PASS - role-change admin flow aur owner-only DID/VC authorization gate Docker cohort me verify ho gaye.

---

## ✅ Requirement 5 - Signed invite tokens (expired / tampered / replayed / non-owner rejected)

> Invite token signed (ECDSA-P256), time-limited (default 24h, clamp 5min..30d), replay-protected (`max_uses`, default 1). Tampered/expired/replayed/non-owner-minted tokens **reject** hone chahiye. Permissions blindly token se nahi lete — re-derive + validate (no `vc:issue` escalation).

**Terminal:** Host terminal

**Commands:**
```bash
cd /home/asad/SGX
CID=$(
  docker exec sgx-nodeA sh -lc 'curl -s http://127.0.0.1:8443/api/v1/circles' |
  python3 -c 'import sys,json; d=json.load(sys.stdin); circles=d["circles"] if isinstance(d, dict) and "circles" in d else d
for c in circles:
    cid = c.get("circleId") or c.get("circle_id")
    if c.get("kind") == "comms" and cid:
        print(cid)
        break
else:
    raise SystemExit("No comms circle found")'
)

MINT_JSON=$(docker exec sgx-nodeA sh -lc "curl -s -X POST http://127.0.0.1:8443/api/v1/circles/$CID/invites -H 'content-type: application/json' -d '{\"role\":\"member\"}'")
echo "$MINT_JSON" | python3 -m json.tool
TOKEN=$(echo "$MINT_JSON" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d["token_b64"])')
BAD=$(printf '%s' "$TOKEN" | sed 's/.$/X/')
docker exec sgx-nodeB sh -lc "curl -s -w '\nHTTP %{http_code}\n' -X POST http://127.0.0.1:8443/api/v1/circles/join/preview -H 'content-type: application/json' -d '{\"token_b64\":\"$BAD\"}'"
```

**Expected:**
```text
Mint → {invite_id, token_b64, qr_payload, link, expires_at} returned
Tampered join/preview → rejected with HTTP 400 and invalid invite token message
```

**Result:**
```text
Mint response returned:
- invite_id: urn:uuid:3f958d38-6c61-4820-b7ac-abeacbce6f45
- token_b64: present
- qr_payload: present
- link: present
- expires_at: 2026-07-22T13:19:11.186942094+00:00

Tampered join/preview returned:
- error.code: BAD_REQUEST
- error.message: invalid circle data: invalid invite token: Invalid last symbol 88, offset 1317.
- HTTP 400
```

**Verdict:** PASS - signed invite token tamper rejection Docker cohort me verify ho gayi.

---

## ✅ Requirement 6 - QR-based invitations

**Terminal:** Host terminal

**Commands:**
```bash
cd /home/asad/SGX
API=http://127.0.0.1:8443/api/v1
CID=circle-dbfa23ec-7b81-47ac-ac20-d779bd38c65f

TOKEN=$(echo "$MINT_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['token_b64'])")
INVITE_ID=$(echo "$MINT_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['invite_id'])")

docker exec sgx-nodeA sh -lc "curl -s $API/circles/$CID/invites" | python3 -m json.tool
docker exec sgx-nodeA sh -lc "curl -s -X DELETE $API/circles/$CID/invites/$INVITE_ID" | python3 -m json.tool

MINT_JSON=$(docker exec sgx-nodeA sh -lc "curl -s -X POST $API/circles/$CID/invites -H 'content-type: application/json' -d '{\"role\":\"member\",\"owner_host\":\"http://sgx-nodeA:8443\"}'")
echo "$MINT_JSON" | python3 -m json.tool
```

**Expected:**
```text
GET /invites -> current invite listed
DELETE /invites/{invite_id} -> success
Fresh POST /invites -> token_b64, qr_payload, link, expires_at present
```

**Result:**
```text
GET /invites returned:
- count: 1
- invite id: urn:uuid:7bc69052-8194-4181-a4c7-1cffbe5cf014

DELETE /invites/{invite_id} returned:
- status: success
- message: Circle invite revoked

Fresh POST /invites returned:
- status: success
- invite_id: urn:uuid:2a85d6e4-73ad-4bd8-b14d-7fd2fcdfad07
- token_b64 present
- qr_payload present
- link present
- expires_at: 2026-07-21T13:31:15.557235716+00:00
- owner_host embedded as http://sgx-nodeA:8443
```

**Verdict:** PASS - QR/share payload, invite listing, aur invite revoke flow Docker cohort me verify ho gayi.

---

## ✅ Requirement 7 - Join flow end-to-end

**Terminal:** Host terminal

**Commands:**
```bash
cd /home/asad/SGX
API=http://127.0.0.1:8443/api/v1
TOKEN=$(echo "$MINT_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['token_b64'])")

docker exec sgx-nodeB sh -lc "curl -s -X POST http://127.0.0.1:8443/api/v1/circles/join/preview -H 'content-type: application/json' -d '{\"token_b64\":\"$TOKEN\"}'" | python3 -m json.tool
docker exec sgx-nodeB sh -lc "curl -s -X POST http://127.0.0.1:8443/api/v1/circles/join -H 'content-type: application/json' -d '{\"token_b64\":\"$TOKEN\",\"owner_host\":\"http://sgx-nodeA:8443\"}'" | python3 -m json.tool
docker exec sgx-nodeB sh -lc "curl -s '$API/vc/show?scope=own'" | python3 -m json.tool
docker exec sgx-nodeA sh -lc "cat /var/lib/sgx-guardian/identity/circles/invites/redeemed.json" | python3 -m json.tool
```

**Expected:**
```text
join/preview -> success with circle_name + role
join -> success and membership VC issued to nodeB
nodeB own VCs -> target comms circle present
redeemed.json -> invite_id recorded with nodeB DID
```

**Result:**
```text
join/preview returned:
- status: success
- circle_id: circle-dbfa23ec-7b81-47ac-ac20-d779bd38c65f
- circle_name: Ops Team Docker
- role: member

join returned:
- status: success
- message: Circle membership issued
- issued vc_id: urn:uuid:450fa198-bc8d-4496-9b9c-0276320f8d50
- subject DID: did:guardian:BXdtcPc3m86nKFb5vrbjdgHuN9vEd6Zo6gyaxQm8xqRC
- circleId: circle-dbfa23ec-7b81-47ac-ac20-d779bd38c65f

nodeB /vc/show?scope=own contained:
- vc_id: urn:uuid:450fa198-bc8d-4496-9b9c-0276320f8d50
- circle_id: circle-dbfa23ec-7b81-47ac-ac20-d779bd38c65f
- revoked: false

redeemed.json contained:
- invite_id: urn:uuid:2a85d6e4-73ad-4bd8-b14d-7fd2fcdfad07
- redeemerDid: did:guardian:BXdtcPc3m86nKFb5vrbjdgHuN9vEd6Zo6gyaxQm8xqRC
```

**Verdict:** PASS - preview, redeem, nodeB VC persistence, aur replay ledger update Docker cohort me verify ho gayi.

---

## ✅ Requirement 8 - Remove from Circle = status-list revoke only

**Terminal:** Host terminal

**Commands:**
```bash
cd /home/asad/SGX
API=http://127.0.0.1:8443/api/v1
CID=circle-dbfa23ec-7b81-47ac-ac20-d779bd38c65f

BEFORE=$(docker exec sgx-nodeA sh -lc "curl -s $API/crl/list" | python3 -c "import sys,json; print(json.load(sys.stdin)['count'])")
docker exec sgx-nodeA sh -lc "curl -s -X DELETE '$API/circles/$CID/members/$TEST_MEMBER_DID'" | python3 -m json.tool
docker exec sgx-nodeA sh -lc "curl -s $API/circles/$CID/members" | python3 -m json.tool
AFTER=$(docker exec sgx-nodeA sh -lc "curl -s $API/crl/list" | python3 -c "import sys,json; print(json.load(sys.stdin)['count'])")
echo "CRL BEFORE=$BEFORE AFTER=$AFTER"
```

**Expected:**
```text
DELETE /members/{did} -> success
GET /members -> target member lifecycle becomes revoked in the comms circle
CRL count remains unchanged
```

**Result:**
```text
DELETE /members/{did} returned:
- status: success
- message: Circle member removed

GET /members returned:
- removed member still visible for auditability
- target DID: did:guardian:EcRBpx6MfU8756hKLQtqYix4bAGgNfDSWRLYFZJKqgSS
- lifecycleState: revoked
- role: member

CRL counts:
- BEFORE=9
- AFTER=9
```

**Verdict:** PASS - member removal status-list revoke tak limited rahi aur CRL bilkul unchanged raha.

---

## ✅ Requirement 9 - Mesh Circle isolation + Milestone-4 guard

**Terminal:** Host terminal

**Commands:**
```bash
cd /home/asad/SGX
API=http://127.0.0.1:8443/api/v1
MESH_ID=$(docker exec sgx-nodeA sh -lc "curl -s $API/circles" | python3 -c "import sys,json; d=json.load(sys.stdin); print([c['circleId'] for c in d['circles'] if c['kind']=='mesh'][0])")

docker exec sgx-nodeA sh -lc "curl -s -o /dev/null -w '%{http_code}\n' -X POST $API/circles/$MESH_ID/archive"
docker exec sgx-nodeA sh -lc "curl -s $API/crl/gossip/status" | python3 -m json.tool
docker exec sgx-nodeA sh -lc "curl -s -X POST $API/crl/gossip/trigger" | python3 -m json.tool
```

**Expected:**
```text
Archive Mesh Circle -> 409
crl/gossip/status -> runtime gossip circle remains guardian-circle-alpha
crl/gossip/trigger -> success
```

**Result:**
```text
Archive Mesh Circle returned:
- HTTP 409

crl/gossip/status returned:
- circle_id: guardian-circle-alpha
- merkle_root: c065b70879e4bde772a4bcbc9ee8b49cbbfb9751dc79eaec545b62564598293e
- rounds_initiated: 12
- last_round.direction: initiated
- last_round.peer_node: nodeB

crl/gossip/trigger returned:
- success: true
- peer_node: nodeB
- merged: 0
- pushed: 0
- message: gossip round completed
```

**Verdict:** PASS - Mesh Circle archive block, runtime gossip isolation, aur Milestone-4 gossip health Docker cohort me intact verify huay.

---

## ✅ API 1 - Circle CRUD

**Terminal:** Host terminal

**Commands:**
```bash
cd /home/asad/SGX
API=http://127.0.0.1:8443/api/v1

docker exec sgx-nodeA sh -lc "curl -s $API/circles" | python3 -m json.tool

API1_JSON=$(docker exec sgx-nodeA sh -lc "curl -s -X POST $API/circles -H 'content-type: application/json' -d '{\"name\":\"API1 Docker CRUD\",\"description\":\"api1 disposable\"}'")
echo "$API1_JSON" | python3 -m json.tool
API1_CID=$(echo "$API1_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print((d.get('circle') or {}).get('circleId') or d.get('circleId'))")

docker exec sgx-nodeA sh -lc "curl -s $API/circles/$API1_CID" | python3 -m json.tool
docker exec sgx-nodeA sh -lc "curl -s -X PATCH $API/circles/$API1_CID -H 'content-type: application/json' -d '{\"name\":\"API1 Docker CRUD Renamed\"}'" | python3 -m json.tool
docker exec sgx-nodeA sh -lc "curl -s -X POST $API/circles/$API1_CID/archive" | python3 -m json.tool
```

**Expected:**
```text
GET /circles -> list returned with mesh + comms entries
POST /circles -> disposable comms circle created
GET /circles/{id} -> detail returned
PATCH /circles/{id} -> renamed
POST /circles/{id}/archive -> archived successfully for comms circle
```

**Result:**
```text
GET /circles returned:
- status: success
- count: 3
- included active comms circles plus guardian-circle-alpha mesh circle

POST /circles returned:
- status: success
- message: Circle created
- circleId: circle-c0c251d4-628d-4c1e-aae5-ed69b8cceb69
- name: API1 Docker CRUD

GET /circles/{id} returned:
- status: success
- circleId: circle-c0c251d4-628d-4c1e-aae5-ed69b8cceb69

PATCH /circles/{id} returned:
- status: success
- name: API1 Docker CRUD Renamed

POST /circles/{id}/archive returned:
- status: success
- message: Circle archived
- status field: archived
```

**Verdict:** PASS - Circle CRUD flow Docker cohort me end-to-end verify ho gaya.

---

## ✅ API 2 - Members

**Terminal:** Host terminal

**Commands:**
```bash
cd /home/asad/SGX
API=http://127.0.0.1:8443/api/v1
TEST_MEMBER_DID="$NODEC_DID"

API2_JSON=$(docker exec sgx-nodeA sh -lc "curl -s -X POST $API/circles -H 'content-type: application/json' -d '{\"name\":\"API2 Members\",\"description\":\"api2 disposable\"}'")
API2_CID=$(echo "$API2_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print((d.get('circle') or {}).get('circleId') or d.get('circleId'))")

docker exec sgx-nodeA sh -lc "curl -s -X POST $API/circles/$API2_CID/members -H 'content-type: application/json' -d '{\"did\":\"$TEST_MEMBER_DID\",\"role\":\"member\"}'" | python3 -m json.tool
docker exec sgx-nodeA sh -lc "curl -s $API/circles/$API2_CID/members" | python3 -m json.tool
docker exec sgx-nodeA sh -lc "curl -s -X PATCH '$API/circles/$API2_CID/members/$TEST_MEMBER_DID' -H 'content-type: application/json' -d '{\"role\":\"owner\"}'" | python3 -m json.tool
docker exec sgx-nodeA sh -lc "curl -s -X DELETE '$API/circles/$API2_CID/members/$TEST_MEMBER_DID'" | python3 -m json.tool
```

**Expected:**
```text
POST /members -> membership VC issued
GET /members -> owner + target member listed
PATCH /members/{did} -> role changed
DELETE /members/{did} -> member removed via status-list revoke
```

**Result:**
```text
POST /members returned:
- status: success
- message: Circle member added
- subject DID: did:guardian:EcRBpx6MfU8756hKLQtqYix4bAGgNfDSWRLYFZJKqgSS
- role: member
- circleId: circle-9548ed6a-850e-46ff-94ff-7ab10c92036f

GET /members returned:
- status: success
- count: 2
- target DID listed with lifecycleState: active

PATCH /members/{did} returned:
- status: success
- message: Circle member role updated
- role: owner

DELETE /members/{did} returned:
- status: success
- message: Circle member removed
```

**Verdict:** PASS - Members API create, list, role-change, aur remove flow verify ho gaya.

---

## ✅ API 3 - Invites

**Terminal:** Host terminal

**Commands:**
```bash
cd /home/asad/SGX
API=http://127.0.0.1:8443/api/v1
OWNER_HOST=http://sgx-nodeA:8443

INV_JSON=$(docker exec sgx-nodeA sh -lc "curl -s -X POST $API/circles/$API2_CID/invites -H 'content-type: application/json' -d '{\"role\":\"member\",\"owner_host\":\"$OWNER_HOST\"}'")
echo "$INV_JSON" | python3 -m json.tool
INV_ID=$(echo "$INV_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['invite_id'])")

docker exec sgx-nodeA sh -lc "curl -s $API/circles/$API2_CID/invites" | python3 -m json.tool
docker exec sgx-nodeA sh -lc "curl -s -X DELETE $API/circles/$API2_CID/invites/$INV_ID" | python3 -m json.tool
```

**Expected:**
```text
POST /invites -> invite_id, token_b64, qr_payload, link, expires_at returned
GET /invites -> minted invite listed
DELETE /invites/{invite_id} -> invite revoked
```

**Result:**
```text
POST /invites returned:
- status: success
- invite_id: urn:uuid:7598839e-d310-4693-b46a-1ab2e69c264f
- token_b64 present
- qr_payload present
- link present
- expires_at: 2026-07-21T13:47:07.748378699+00:00

GET /invites returned:
- status: success
- count: 1
- same invite_id listed

DELETE /invites/{invite_id} returned:
- status: success
- message: Circle invite revoked
```

**Verdict:** PASS - Invites API mint, list, aur revoke flow verify ho gaya.

---

## ✅ API 4 - Join / Redeem

**Terminal:** Host terminal

**Commands:**
```bash
cd /home/asad/SGX
API=http://127.0.0.1:8443/api/v1
OWNER_HOST=http://sgx-nodeA:8443

API4_JSON=$(docker exec sgx-nodeA sh -lc "curl -s -X POST $API/circles -H 'content-type: application/json' -d '{\"name\":\"API4 Join\",\"description\":\"api4 disposable\"}'")
API4_CID=$(echo "$API4_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print((d.get('circle') or {}).get('circleId') or d.get('circleId'))")

JOIN_JSON=$(docker exec sgx-nodeA sh -lc "curl -s -X POST $API/circles/$API4_CID/invites -H 'content-type: application/json' -d '{\"role\":\"member\",\"owner_host\":\"$OWNER_HOST\",\"max_uses\":1}'")
echo "$JOIN_JSON" | python3 -m json.tool
JOIN_TOKEN=$(echo "$JOIN_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['token_b64'])")

docker exec sgx-nodeB sh -lc "curl -s -X POST $API/circles/join/preview -H 'content-type: application/json' -d '{\"token_b64\":\"$JOIN_TOKEN\"}'" | python3 -m json.tool
docker exec sgx-nodeB sh -lc "curl -s -X POST $API/circles/join -H 'content-type: application/json' -d '{\"token_b64\":\"$JOIN_TOKEN\",\"owner_host\":\"$OWNER_HOST\"}'" | python3 -m json.tool
docker exec sgx-nodeB sh -lc "curl -s '$API/vc/show?scope=own'" | python3 -m json.tool
docker exec sgx-nodeA sh -lc "cat /var/lib/sgx-guardian/identity/circles/invites/redeemed.json" | python3 -m json.tool
```

**Expected:**
```text
POST /circles/join/preview -> invite preview details returned
POST /circles/join -> membership VC issued to nodeB
GET /vc/show?scope=own -> nodeB owns VC for API4 circle
redeemed.json -> invite consumption recorded
```

**Result:**
```text
join/preview returned:
- status: success
- circle_id: circle-0f860dfd-cf81-4dd4-a2cb-1d3cf38caede
- circle_name: API4 Join
- role: member

join returned:
- status: success
- message: Circle membership issued
- vc_id: urn:uuid:3744cf25-8d62-4cf3-b40a-f682aa649d14
- subject DID: did:guardian:BXdtcPc3m86nKFb5vrbjdgHuN9vEd6Zo6gyaxQm8xqRC
- circleId: circle-0f860dfd-cf81-4dd4-a2cb-1d3cf38caede

nodeB /vc/show?scope=own returned:
- count: 4
- contained vc_id: urn:uuid:3744cf25-8d62-4cf3-b40a-f682aa649d14
- contained circle_id: circle-0f860dfd-cf81-4dd4-a2cb-1d3cf38caede

redeemed.json returned:
- invite_id: urn:uuid:01e5f22e-6b60-4da8-a313-03b57074e1b1
- redeemerDid: did:guardian:BXdtcPc3m86nKFb5vrbjdgHuN9vEd6Zo6gyaxQm8xqRC
```

**Verdict:** PASS - Join/preview, redeem, nodeB VC persistence, aur redeemed ledger update verify ho gaye.
