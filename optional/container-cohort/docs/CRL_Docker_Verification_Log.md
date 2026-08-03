# Certificate Revocation List (CRL) — Docker Verification Log
**Environment:** Docker container cohort (WSL2) | **Date:** 2026-07-16 | **Tester:** Asad Ali

---

## 📌 Task Description

> **CRL Gossip — CRL Data Structure**
>
> Design Certificate Revocation List (CRL) data structure for peer-to-peer revocation propagation. CRL entry contains: revoked DID, device_id, user_id, Circle_id, revocation reason (compromised/lost/stolen/policy violation), severity level, timestamp, revoker's DID, cryptographic signature. CRL stored in distributed, Certificate Revocation List entity. Each entry cryptographically signed by issuer (Circle owner or member reporting compromise).

---

## 📋 Docker Notes

- Saari commands **host terminal** se chalani hain.
- `sgx-nodeA` = Owner node, REST port `18443`
- `sgx-nodeB` = Member node, REST port `28443`
- `sgx-nodeC` = Extra peer node, REST port `38443`
- Container ke andar `python3` installed nahi hai, is liye JSON parsing host par karo:
  - Sahi pattern: `docker exec sgx-nodeA cat /path/file.json | python3 -m json.tool`
  - Ghalat pattern: `docker exec sgx-nodeA sh -lc "python3 ..."`
- Jahan `RUN_ID` use ho raha hai, har fresh run me nayi values banengi. UUIDs aur sequence values bhi change hongi.

---

## 📊 Requirements Checklist (7 Requirements)

- [ ] Requirement 1 — CRL data structure with all spec-required fields
- [ ] Requirement 2 — Revocation reasons (compromised / lost / stolen / policy_violation)
- [ ] Requirement 3 — Severity levels (critical / high / medium / low)
- [ ] Requirement 4 — Cryptographic signature on each entry (ecdsa-2019)
- [ ] Requirement 5 — Distributed CRL storage with Merkle root integrity
- [ ] Requirement 6 — Peer-to-peer gossip propagation support
- [ ] Requirement 7 — Issuer authorization (owner vs member roles)

---

## 📊 API Checklist (6 APIs from original spec + 1 bonus fix = 7 total)

- [ ] API 1 — POST `/api/v1/crl/revoke`
- [ ] API 2 — GET  `/api/v1/crl/list`
- [ ] API 3 — GET  `/api/v1/crl/entry?id=`
- [ ] API 4 — GET  `/api/v1/crl/check?did=`
- [ ] API 5 — POST `/api/v1/crl/verify`
- [ ] API 6 — GET  `/api/v1/crl/root`
- [ ] API 7 — POST `/api/v1/crl/unrevoke`

---

## 🔧 Session Bootstrap

**Commands:**
```bash
# Host shell
RUN_ID=$(date +%s)

NODEA_DID=$(docker exec sgx-nodeA cat /var/lib/sgx-guardian/identity/did.json | python3 -c "import sys,json; print(json.load(sys.stdin)['did'])")
NODEB_DID=$(docker exec sgx-nodeB cat /var/lib/sgx-guardian/identity/did.json | python3 -c "import sys,json; print(json.load(sys.stdin)['did'])")
NODEC_DID=$(docker exec sgx-nodeC cat /var/lib/sgx-guardian/identity/did.json | python3 -c "import sys,json; print(json.load(sys.stdin)['did'])")

REQ1_DID="did:guardian:docker-req1-$RUN_ID"
LOST_DID="did:guardian:docker-lost-$RUN_ID"
STOLEN_DID="did:guardian:docker-stolen-$RUN_ID"
POLICY_DID="did:guardian:docker-policy-$RUN_ID"
LOW_DID="did:guardian:docker-low-$RUN_ID"
API_DID="did:guardian:docker-api-$RUN_ID"
OWNER_DUP_DID="did:guardian:docker-owner-dup-$RUN_ID"
MEMBER_OK_DID="did:guardian:docker-member-ok-$RUN_ID"
MEMBER_MED_DID="did:guardian:docker-member-medium-$RUN_ID"
MEMBER_BAD_DID="did:guardian:docker-member-bad-$RUN_ID"

echo "$NODEA_DID"
echo "$NODEB_DID"
echo "$NODEC_DID"
```

**Expected output:**
```text
did:guardian:...
did:guardian:...
did:guardian:...
```

---

## ✅ Requirement 1 — CRL data structure with all spec-required fields

> CRL entry must contain `revoked_did`, `device_id`, `user_id`, `circle_id`, `reason`, `severity`, `timestamp`, `revoker_did`, `revoker_role`, and cryptographic `proof`.

**Commands:**
```bash
# NodeA / Owner
docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeA \
  sgx-pa-cli crl revoke \
  --did "$REQ1_DID" \
  --reason compromised \
  --severity critical \
  --device-id "se050-$RUN_ID" \
  --user-id "user-$RUN_ID" \
  --note "req1 structure check"
```

```bash
# NodeA file read, host-side JSON formatting
docker exec sgx-nodeA cat /var/lib/sgx-guardian/identity/crl/crl.json | python3 -m json.tool
```

**Expected output:**
```text
✅ CRL entry issued: urn:uuid:... (sequence=N, root=...)
```

```json
{
  "issuer": "did:guardian:...",
  "circle_id": "guardian-circle-alpha",
  "sequence": N,
  "merkle_root": "...",
  "entries": [
    {
      "revoked_did": "did:guardian:docker-req1-...",
      "device_id": "se050-...",
      "user_id": "user-...",
      "circle_id": "guardian-circle-alpha",
      "reason": "compromised",
      "severity": "critical",
      "timestamp": "...",
      "revoker_did": "did:guardian:...",
      "revoker_role": "owner",
      "proof": {
        "type": "DataIntegrityProof",
        "cryptosuite": "ecdsa-2019",
        "verificationMethod": "did:guardian:...#dkp-v1",
        "proofPurpose": "assertionMethod",
        "proofValue": "..."
      }
    }
  ]
}
```

---

## ✅ Requirement 2 — Revocation reasons

> Mandatory reasons to verify: `compromised`, `lost`, `stolen`, `policy_violation`.

**Commands:**
```bash
# NodeA / Owner
docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeA sgx-pa-cli crl revoke --did "$LOST_DID" --reason lost --severity high --note "req2 lost"
docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeA sgx-pa-cli crl revoke --did "$STOLEN_DID" --reason stolen --severity high --note "req2 stolen"
docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeA sgx-pa-cli crl revoke --did "$POLICY_DID" --reason policy_violation --severity medium --note "req2 policy"
docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeA sgx-pa-cli crl list
```

**Expected output:**
```text
✅ CRL entry issued: urn:uuid:... (sequence=N, root=...)
✅ CRL entry issued: urn:uuid:... (sequence=N, root=...)
✅ CRL entry issued: urn:uuid:... (sequence=N, root=...)

CRL Entries (... total)
... lost ...
... stolen ...
... policy_violation ...
... compromised ...
```

---

## ✅ Requirement 3 — Severity levels

> Severity levels to verify: `critical`, `high`, `medium`, `low`.

**Commands:**
```bash
# NodeA / Owner
docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeA \
  sgx-pa-cli crl revoke \
  --did "$LOW_DID" \
  --reason administrative_removal \
  --severity low \
  --note "req3 low severity"
```

```bash
# NodeA / Owner
docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeA sgx-pa-cli crl check --did "$LOW_DID"
```

**Expected output:**
```text
✅ CRL entry issued: urn:uuid:... (sequence=N, root=...)
```

```json
{
  "did": "did:guardian:docker-low-...",
  "revoked": true,
  "entry": {
    "reason": "administrative_removal",
    "severity": "low",
    "revoker_role": "owner"
  }
}
```

---

## ✅ Requirement 4 — Cryptographic signature on each entry (ecdsa-2019)

> Positive verify must pass, tamper without re-signing must fail, restore must pass again.

**Commands:**
```bash
# NodeA / Owner - before tamper
docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeA sgx-pa-cli crl verify
```

```bash
# NodeA - backup + host copy
docker exec sgx-nodeA sh -lc 'cp /var/lib/sgx-guardian/identity/crl/crl.json /var/lib/sgx-guardian/identity/crl/crl.json.bak2'
docker cp sgx-nodeA:/var/lib/sgx-guardian/identity/crl/crl.json /tmp/crl-nodeA.json
```

```bash
# Host - tamper LOW_DID severity without re-signing
LOW_DID="$LOW_DID" python3 - <<'PY'
import json, os
p="/tmp/crl-nodeA.json"
d=json.load(open(p))
for e in d["entries"]:
    if e["revoked_did"] == os.environ["LOW_DID"]:
        print("BEFORE severity:", e["severity"])
        e["severity"] = "critical"
        print("AFTER severity:", e["severity"])
        break
else:
    raise SystemExit("LOW_DID not found")
json.dump(d, open(p, "w"), indent=2)
PY
```

```bash
# Host -> NodeA
docker cp /tmp/crl-nodeA.json sgx-nodeA:/var/lib/sgx-guardian/identity/crl/crl.json
```

```bash
# NodeA - verify must FAIL
docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeA sgx-pa-cli crl verify
```

```bash
# NodeA - restore + verify PASS again
docker exec sgx-nodeA sh -lc 'cp /var/lib/sgx-guardian/identity/crl/crl.json.bak2 /var/lib/sgx-guardian/identity/crl/crl.json'
docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeA sgx-pa-cli crl verify
```

**Expected output:**
```text
✅ CRL verified
BEFORE severity: low
AFTER severity: critical
❌ invalid signature on CRL entry urn:uuid:...
✅ CRL verified
```

---

## ✅ Requirement 5 — Distributed CRL storage with Merkle root integrity

> CLI root, REST root, and raw `crl.json` root/sequence must match.

**Commands:**
```bash
# NodeA / Owner
docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeA sgx-pa-cli crl root
```

```bash
# Host REST check to nodeA
curl -s http://localhost:18443/api/v1/crl/root | python3 -m json.tool
```

```bash
# NodeA file read, host-side parse
docker exec sgx-nodeA cat /var/lib/sgx-guardian/identity/crl/crl.json | python3 -c "import json,sys; d=json.load(sys.stdin); print({'sequence': d['sequence'], 'merkle_root': d['merkle_root']})"
```

**Expected output:**
```text
{
  "merkle_root": "...",
  "sequence": N
}
```

```json
{
  "sequence": N,
  "merkle_root": "..."
}
```

```text
{'sequence': N, 'merkle_root': '...'}
```

---

## ✅ Requirement 6 — Peer-to-peer gossip propagation support

> Docker build in this run showed gossip metadata populated on stored entries.

**Commands:**
```bash
# NodeA raw file grep
docker exec sgx-nodeA cat /var/lib/sgx-guardian/identity/crl/crl.json | grep -E '"peers_notified"|"propagated"'
```

```bash
# REST list from nodeA
curl -s http://localhost:18443/api/v1/crl/list | python3 -m json.tool
```

**Expected output:**
```text
"peers_notified": [
"propagated": true
```

```json
{
  "status": "success",
  "count": N,
  "entries": [
    {
      "peers_notified": [
        "did:guardian:...",
        "did:guardian:..."
      ],
      "propagated": true
    }
  ]
}
```

---

## ✅ Requirement 7 — Issuer authorization (owner vs member roles)

> Owner can revoke freely; self-revoke is rejected; double-revoke is rejected; member can revoke only for security-critical reasons with `critical` or `high`.

**Commands:**
```bash
# NodeA / Owner - self revoke rejection
docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeA \
  sgx-pa-cli crl revoke \
  --did "$NODEA_DID" \
  --reason compromised \
  --severity critical
```

```bash
# NodeA / Owner - first revoke
docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeA \
  sgx-pa-cli crl revoke \
  --did "$OWNER_DUP_DID" \
  --reason compromised \
  --severity critical \
  --note "req7 owner first"
```

```bash
# NodeA / Owner - second revoke of same DID must reject
docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeA \
  sgx-pa-cli crl revoke \
  --did "$OWNER_DUP_DID" \
  --reason stolen \
  --severity critical \
  --note "req7 owner second"
```

```bash
# NodeB / Member - allowed path
docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeB \
  sgx-pa-cli crl revoke \
  --did "$MEMBER_OK_DID" \
  --reason compromised \
  --severity critical \
  --note "req7 member allowed"
```

```bash
# NodeB / Member - confirm role
docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeB sgx-pa-cli crl check --did "$MEMBER_OK_DID"
```

```bash
# NodeB / Member - medium severity reject
docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeB \
  sgx-pa-cli crl revoke \
  --did "$MEMBER_MED_DID" \
  --reason compromised \
  --severity medium \
  --note "req7 member medium reject"
```

```bash
# NodeB / Member - bad reason reject
docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeB \
  sgx-pa-cli crl revoke \
  --did "$MEMBER_BAD_DID" \
  --reason voluntary_departure \
  --severity critical \
  --note "req7 member bad reason reject"
```

**Expected output:**
```text
❌ revoker may not revoke themselves
✅ CRL entry issued: urn:uuid:... (sequence=N, root=...)
❌ DID is already revoked (entry did:guardian:docker-owner-dup-...)
✅ CRL entry issued: urn:uuid:... (sequence=N, root=...)
❌ member-issued entries must be Critical or High severity (got Medium)
❌ member-issued entries must be a security-critical reason (got voluntary_departure)
```

```json
{
  "did": "did:guardian:docker-member-ok-...",
  "revoked": true,
  "entry": {
    "revoker_role": "member",
    "reason": "compromised",
    "severity": "critical"
  }
}
```

---

## ✅ API 1 — POST `/api/v1/crl/revoke`

**Commands:**
```bash
# Host REST to nodeA
API1_JSON=$(curl -s -X POST http://localhost:18443/api/v1/crl/revoke \
  -H "Content-Type: application/json" \
  -d "{\"did\":\"$API_DID\",\"reason\":\"compromised\",\"severity\":\"critical\",\"device_id\":\"se050-api-test\",\"note\":\"api1 revoke test\"}")

echo "$API1_JSON" | python3 -m json.tool
ENTRY_ID=$(echo "$API1_JSON" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['entry']['id'])")
echo "$ENTRY_ID"
```

**Expected output:**
```json
{
  "status": "success",
  "message": "CRL entry issued",
  "entry": {
    "id": "urn:uuid:...",
    "revoked_did": "did:guardian:docker-api-...",
    "reason": "compromised",
    "severity": "critical",
    "revoker_role": "owner",
    "proof": {
      "type": "DataIntegrityProof",
      "cryptosuite": "ecdsa-2019"
    }
  },
  "sequence": N,
  "merkle_root": "..."
}
```

```text
urn:uuid:...
```

---

## ✅ API 2 — GET `/api/v1/crl/list`

**Commands:**
```bash
# Host REST to nodeA
curl -s http://localhost:18443/api/v1/crl/list | python3 -m json.tool
```

**Expected output:**
```json
{
  "status": "success",
  "count": N,
  "entries": [
    {
      "id": "urn:uuid:...",
      "revoked_did": "did:guardian:docker-api-..."
    }
  ]
}
```

---

## ✅ API 3 — GET `/api/v1/crl/entry?id=`

**Commands:**
```bash
# Host REST to nodeA
curl -s "http://localhost:18443/api/v1/crl/entry?id=$ENTRY_ID" | python3 -m json.tool
```

**Expected output:**
```json
{
  "id": "urn:uuid:...",
  "revoked_did": "did:guardian:docker-api-...",
  "reason": "compromised",
  "severity": "critical",
  "revoker_role": "owner"
}
```

---

## ✅ API 4 — GET `/api/v1/crl/check?did=`

**Commands:**
```bash
# Host REST to nodeA
curl -s "http://localhost:18443/api/v1/crl/check?did=$API_DID" | python3 -m json.tool
```

**Expected output:**
```json
{
  "status": "success",
  "did": "did:guardian:docker-api-...",
  "revoked": true,
  "entry": {
    "id": "urn:uuid:...",
    "reason": "compromised",
    "severity": "critical"
  }
}
```

---

## ✅ API 5 — POST `/api/v1/crl/verify`

**Commands:**
```bash
# Host REST to nodeA
curl -s -X POST http://localhost:18443/api/v1/crl/verify | python3 -m json.tool
```

**Expected output:**
```json
{
  "ok": true,
  "errors": []
}
```

---

## ✅ API 6 — GET `/api/v1/crl/root`

**Commands:**
```bash
# Host REST to nodeA
curl -s http://localhost:18443/api/v1/crl/root | python3 -m json.tool
```

**Expected output:**
```json
{
  "sequence": N,
  "merkle_root": "..."
}
```

---

## ✅ API 7 — POST `/api/v1/crl/unrevoke`

**Commands:**
```bash
# Host REST to nodeA
curl -s -X POST http://localhost:18443/api/v1/crl/unrevoke \
  -H "Content-Type: application/json" \
  -d "{\"did\":\"$API_DID\"}" | python3 -m json.tool
```

**Expected output:**
```json
{
  "status": "success",
  "message": "CRL entry unrevoked",
  "did": "did:guardian:docker-api-...",
  "sequence": N,
  "merkle_root": "..."
}
```

---

## ✅ Final Expected State

If sab kuch sahi chale, to final summary ye honi chahiye:

```text
Requirement 1: PASS
Requirement 2: PASS
Requirement 3: PASS
Requirement 4: PASS
Requirement 5: PASS
Requirement 6: PASS
Requirement 7: PASS

API 1: PASS
API 2: PASS
API 3: PASS
API 4: PASS
API 5: PASS
API 6: PASS
API 7: PASS
```

