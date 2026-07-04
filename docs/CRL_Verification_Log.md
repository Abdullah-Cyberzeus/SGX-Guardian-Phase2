# Certificate Revocation List (CRL) — Verification Log
**Board:** iMX8MP (ARM64) | **Branch:** Aliza_Malik | **Tester:** Asad Ali

---

## 📌 Task Description

> **CRL Gossip — CRL Data Structure**
>
> Design Certificate Revocation List (CRL) data structure for peer-to-peer revocation propagation. CRL entry contains: revoked DID, device_id, user_id, Circle_id, revocation reason (compromised/lost/stolen/policy violation), severity level, timestamp, revoker's DID, cryptographic signature. CRL stored in distributed, Certificate Revocation List entity. Each entry cryptographically signed by issuer (Circle owner or member reporting compromise).

---

## 📋 How to Use This File

**Jab bhi koi Requirement ya API verify ho jaye (PASS):**
1. `[ ]` ko `[x]` karo aur `## ⏳` ko `## ✅` kar do
2. **Commands:** section mein woh exact command likhna jo run kiya
3. **Result:** section mein terminal output paste karna
4. **Verdict:** ek line mein confirm karna — kya pass hua

**Jab koi Requirement ya API FAIL ho:**
1. **Pehle command side verify karo** — command galat bhi ho sakti hai, code galat nahi bhi ho sakta:
   - Kya command ka syntax theek hai?
   - Kya required service chal rahi hai (Guardian on 8443)?
   - Kya test DID / input valid format mein hai?
   - Alternate command se dobara try karo
2. **Sirf tab `❌` lagao** jab fully confirm ho jaye ke issue code side ka hai, command side ka nahi
3. **`❌` lagane ke saath ye bhi likho:**
   - Konsi file/function mein likely issue hai (e.g. `src/crl/issue.rs:45`) (also dont fully relay on this cross check yourself as well if you think issue not in this file maybe another file)
   - Exact error message jo aaya
   - Kya try kiya aur kya nahi chala

**Requirements count ke baare mein:**
- Requirements ki count task description se derive hoti hai — fixed count number nahi hony chiya
- Jitne distinct verifiable claims task description mein hain utni hi requirements banani hain
- Artificially pad mat karo aur koi genuine requirement miss bhi mat karo

**Symbols:**
- `✅` = Verified and passed
- `❌` = Confirmed code-side failure (command side fully ruled out)
- `⏳` = Not yet tested

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

## 📊 API Checklist (6 APIs)

- [ ] API 1 — POST `/api/v1/crl/revoke`
- [ ] API 2 — GET  `/api/v1/crl/list`
- [ ] API 3 — GET  `/api/v1/crl/entry?id=`
- [ ] API 4 — GET  `/api/v1/crl/check?did=`
- [ ] API 5 — POST `/api/v1/crl/verify`
- [ ] API 6 — GET  `/api/v1/crl/root`

---

## ⏳ Requirement 1 — CRL data structure with all spec-required fields

> CRL entry (`CrlEntry`) contains all specification-required fields: `revoked_did`, `device_id`, `user_id`, `circle_id`, `reason`, `severity`, `timestamp`, `revoker_did`, cryptographic `proof`. Stored as `CertificateRevocationList` container with `sequence`, `merkle_root`, and `issuer`.

**Commands:**
```bash
# After issuing a revocation, inspect the raw CRL file
cat /var/lib/sgx-guardian/crl/crl.json | python3 -m json.tool | head -60
```

**Result:**
```
(pending)
```

**Verdict:** ⏳ Not yet verified

---

## ⏳ Requirement 2 — Revocation reasons (compromised / lost / stolen / policy_violation)

> Supported revocation reasons: `compromised`, `lost`, `stolen`, `policy_violation` (+ `administrative_removal`, `voluntary_departure` for operational use). Security-critical reasons trigger emergency propagation path.

**Commands:**
```bash
# Revoke with each reason type
sgx-pa-cli crl revoke --did did:guardian:test1 --reason compromised --severity critical
sgx-pa-cli crl revoke --did did:guardian:test2 --reason lost --severity high
sgx-pa-cli crl revoke --did did:guardian:test3 --reason stolen --severity high
sgx-pa-cli crl revoke --did did:guardian:test4 --reason policy_violation --severity medium
```

**Result:**
```
(pending)
```

**Verdict:** ⏳ Not yet verified

---

## ⏳ Requirement 3 — Severity levels (critical / high / medium / low)

> Four severity levels supported: `critical`, `high`, `medium`, `low`. Severity determines propagation priority and session-termination behavior.

**Commands:**
```bash
sgx-pa-cli crl revoke --did did:guardian:sev-test --reason compromised --severity critical
sgx-pa-cli crl check --did did:guardian:sev-test
```

**Result:**
```
(pending)
```

**Verdict:** ⏳ Not yet verified

---

## ⏳ Requirement 4 — Cryptographic signature on each entry (ecdsa-2019)

> Each CRL entry is signed by the issuer using their DKP key via `DataIntegrityProof` (ecdsa-2019). Proof is verified against the issuer's DID Document resolved via Sprint 5 Resolver. Gossip fields (`peers_notified`, `propagated`) are excluded from the signed surface.

**Commands:**
```bash
# Check proof field on a CRL entry
cat /var/lib/sgx-guardian/crl/crl.json | python3 -m json.tool | grep -A 8 '"proof"'
# Verify signature
sgx-pa-cli crl verify
```

**Result:**
```
(pending)
```

**Verdict:** ⏳ Not yet verified

---

## ⏳ Requirement 5 — Distributed CRL storage with Merkle root integrity

> CRL is stored in `crl.json` with a `sequence` (monotonically increasing per Circle) and `merkle_root` (SHA-256 over sorted entry fingerprints). Anti-entropy sync uses sequence + Merkle root to detect stale peers.

**Commands:**
```bash
# Check merkle root and sequence
sgx-pa-cli crl root
curl -s http://localhost:8443/api/v1/crl/root | python3 -m json.tool
```

**Result:**
```
(pending)
```

**Verdict:** ⏳ Not yet verified

---

## ⏳ Requirement 6 — Peer-to-peer gossip propagation support

> CRL entries contain pre-allocated gossip fields: `peers_notified` (list of peer DIDs that ack'd receipt) and `propagated` (true once 80% threshold met). Security-critical reasons (`compromised`, `lost`, `stolen`, `policy_violation`) use emergency broadcast channel.

**Commands:**
```bash
# After revocation, check gossip fields in entry
cat /var/lib/sgx-guardian/crl/crl.json | python3 -m json.tool | grep -E "peers_notified|propagated"
```

**Result:**
```
(pending)
```

**Verdict:** ⏳ Not yet verified

---

## ⏳ Requirement 7 — Issuer authorization (owner vs member roles)

> Two revoker roles: `owner` (Circle owner — can revoke any DID for any reason) and `member` (can only report security-critical reasons: compromised/lost/stolen/policy_violation with severity Critical or High). Self-revocation is rejected.

**Commands:**
```bash
# Owner revocation
sgx-pa-cli crl revoke --did did:guardian:peer1 --reason compromised --severity critical
# Check revoker_role in entry
cat /var/lib/sgx-guardian/crl/crl.json | python3 -m json.tool | grep -E "revoker_role|revoker_did"
```

**Result:**
```
(pending)
```

**Verdict:** ⏳ Not yet verified

---

## 🔌 API Verification

### ⏳ API 1 — POST `/api/v1/crl/revoke`

**Command:**
```bash
curl -s -X POST http://localhost:8443/api/v1/crl/revoke \
  -H "Content-Type: application/json" \
  -d '{
    "did": "did:guardian:test-device-001",
    "reason": "compromised",
    "severity": "critical",
    "device_id": "se050-abc123",
    "note": "Key compromise detected via attestation failure"
  }' | python3 -m json.tool
```

**Result:**
```
(pending)
```

**Verdict:** ⏳ Not yet verified

---

### ⏳ API 2 — GET `/api/v1/crl/list`

**Command:**
```bash
curl -s http://localhost:8443/api/v1/crl/list | python3 -m json.tool
```

**Result:**
```
(pending)
```

**Verdict:** ⏳ Not yet verified

---

### ⏳ API 3 — GET `/api/v1/crl/entry?id=`

**Command:**
```bash
# Replace <entry-id> with actual UUID from revoke response
curl -s "http://localhost:8443/api/v1/crl/entry?id=<entry-id>" | python3 -m json.tool
```

**Result:**
```
(pending)
```

**Verdict:** ⏳ Not yet verified

---

### ⏳ API 4 — GET `/api/v1/crl/check?did=`

**Command:**
```bash
curl -s "http://localhost:8443/api/v1/crl/check?did=did:guardian:test-device-001" | python3 -m json.tool
```

**Result:**
```
(pending)
```

**Verdict:** ⏳ Not yet verified

---

### ⏳ API 5 — POST `/api/v1/crl/verify`

**Command:**
```bash
curl -s -X POST http://localhost:8443/api/v1/crl/verify | python3 -m json.tool
```

**Result:**
```
(pending)
```

**Verdict:** ⏳ Not yet verified

---

### ⏳ API 6 — GET `/api/v1/crl/root`

**Command:**
```bash
curl -s http://localhost:8443/api/v1/crl/root | python3 -m json.tool
```

**Result:**
```
(pending)
```

**Verdict:** ⏳ Not yet verified

---

## ⚙️ Known Setup Notes

- Guardian REST API port: **8443**
- CRL storage path: `/var/lib/sgx-guardian/crl/crl.json`
- CRL config: `/etc/sgx-guardian/config/` (node config mein circle_id hoga)
- `sgx-pa-cli crl` commands directly available on board after binary deploy
- API 3 (`entry?id=`) ke liye pehle API 1 (`revoke`) se UUID lena hoga

