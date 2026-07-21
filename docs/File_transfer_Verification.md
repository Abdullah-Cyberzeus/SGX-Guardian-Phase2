# In-Circle File Transfer — Verification Log
**Board:** iMX8MP (ARM64) | **Branch:** TBD | **Tester:** TBD

---

## 📌 Task Description

> **In-Circle File Transfer**
>
> Implement chunked, resumable, signed file transfer between Circle members over the Nebula overlay. Transfer must use a signed manifest, per-chunk SHA-256 verification, whole-file SHA-256 verification, resume support through persisted state, zero-trust inbound validation (including CRL gate), and REST endpoints for send, progress, cancel, and inbox listing. Feature must remain additive and must not break the existing code flow.

---

## 📋 How to Use This File

**Jab bhi koi Requirement ya API verify ho jaye (PASS):**
1. `[ ]` ko `[x]` karo aur `## ⏳` ko `## ✅` kar do
2. **Commands:** section mein woh exact command likhna jo run kiya
3. **Result:** section mein terminal output paste karna
4. **Verdict:** ek line mein confirm karna — kya pass hua

**Jab koi Requirement ya API FAIL ho:**
1. **Pehle command side verify karo** — command galat bhi ho sakti hai, code galat nahi bhi ho sakta:
   - Kya Guardian chal raha hai aur REST API `8443` pe available hai?
   - Kya XFER listener `50064` pe bind hua hua hai?
   - Kya peer DID local peer directory mein maujood hai?
   - Kya sender peer revoke to nahi hai?
   - Kya test file ka path sahi hai aur file max size se chhoti hai?
2. **Sirf tab `❌` lagao** jab fully confirm ho jaye ke issue code side ka hai, command side ka nahi
3. **`❌` lagane ke saath ye bhi likho:**
   - Konsi file/function mein likely issue hai (e.g. `src/xfer/engine.rs:120`)
   - Exact error message jo aaya
   - Kya try kiya aur kya nahi chala

**⚠️ Common mistakes jo dobara na karein:**
- **Peer DID hamesha poori `did:guardian:...` string ke sath use karo** — short/truncated value use mat karo
- **`<...>` angle brackets literally shell mein mat likhna** — ye sirf placeholder marker hain
- **`transfer_id` hamesha current `POST /api/v1/xfer/send` response se lo** — purani run ki id reuse mat karo
- **Send test se pehle port check karo**: `nft list ruleset | grep 50064` aur `ss -lntp | grep 50064`
- **File path sender machine par real hona chahiye** — missing path pe API fail hona expected hai
- **Resume test ke liye same file dubara bhejo** — warna naya `transfer_id` banega aur resume prove nahi hoga
- **Receiver peer active aur non-revoked hona chahiye** — revoked peer ko transfer reject hona expected hai

**Requirements count ke baare mein:**
- Requirements ki count task description se derive hoti hai — fixed count number nahi hony chahiya
- Jitne distinct verifiable claims task description mein hain utni hi requirements banani hain
- Artificially pad mat karo aur koi genuine requirement miss bhi mat karo

**Symbols:**
- `✅` = Verified and passed
- `❌` = Confirmed code-side failure (command side fully ruled out)
- `⏳` = Not yet tested

---

## 📊 Requirements Checklist (8 Requirements)

- [ ] Requirement 1 — Additive module wiring and background listener startup
- [ ] Requirement 2 — Port `50064` reserved and allowed under enforcement
- [ ] Requirement 3 — Signed manifest with all required metadata and proof
- [ ] Requirement 4 — Zero-trust inbound validation path
- [ ] Requirement 5 — Chunked transfer with per-chunk SHA-256 verification
- [ ] Requirement 6 — Resume support via persisted `state.json` / `have_chunks`
- [ ] Requirement 7 — Whole-file SHA-256 verification and atomic inbox publish
- [ ] Requirement 8 — Audit trail and transfer progress observability

---

## 📊 API Checklist (5 APIs)

- [ ] API 1 — POST `/api/v1/xfer/send`
- [ ] API 2 — GET `/api/v1/xfer/transfers`
- [ ] API 3 — GET `/api/v1/xfer/transfers/{id}`
- [ ] API 4 — POST `/api/v1/xfer/transfers/{id}/cancel`
- [ ] API 5 — GET `/api/v1/xfer/inbox`

---

## ⏳ Requirement 1 — Additive module wiring and background listener startup

> File transfer feature must be strictly additive: new `src/xfer/` module, startup spawn in `main.rs`, and no regression to existing flow.

**Commands:**
```bash
cargo build
```
```bash
./sgx_guardian_client nodeB
```
```bash
ss -lntp | grep 50064
```

**Result:**
```text
<paste build result here>
<paste listener/bind result here>
```

**Verdict:** ⏳ Pending — confirm build green, daemon still boots, and XFER listener starts on `50064` without affecting existing services.

---

## ⏳ Requirement 2 — Port `50064` reserved and allowed under enforcement

> nftables ruleset must explicitly allow TCP port `50064`, otherwise transfer silently dies under enforcement.

**Commands:**
```bash
nft list ruleset | grep 50064
```
```bash
ss -lntp | grep 50064
```

**Result:**
```text
<paste nft output here>
<paste listener output here>
```

**Verdict:** ⏳ Pending — confirm `tcp dport 50064 accept` exists and listener is reachable locally.

---

## ⏳ Requirement 3 — Signed manifest with all required metadata and proof

> Manifest must include transfer id, circle id, sender DID, filename, size, chunk bytes/count, chunk digests, whole-file SHA-256, timestamp, and cryptographic proof.

**Commands:**
```bash
curl -s -X POST http://localhost:8443/api/v1/xfer/send \
  -H "Content-Type: application/json" \
  -d '{
    "peer_did": "<real-peer-did>",
    "path": "<real-file-path>"
  }' | python3 -m json.tool
```
```bash
cat /var/lib/sgx-guardian/xfer/outbox/<transfer_id>.json | python3 -m json.tool
```

**Result:**
```text
<paste send response here>
<paste outbox/manifest details here>
```

**Verdict:** ⏳ Pending — confirm manifest-backed transfer has required metadata and a valid signed proof surface.

---

## ⏳ Requirement 4 — Zero-trust inbound validation path

> Receiver must validate: message kind, circle match, sender != self, sender not revoked, sender present in peer directory, and manifest proof verifies against sender DID Document.

**Commands:**
```bash
curl -s -X POST http://localhost:8443/api/v1/xfer/send \
  -H "Content-Type: application/json" \
  -d '{
    "peer_did": "<revoked-or-invalid-peer-did>",
    "path": "<real-file-path>"
  }' | python3 -m json.tool
```
```bash
grep -i xfer /var/log/sgx-guardian/*.log
```

**Result:**
```text
<paste rejection/error here>
<paste audit/log line here>
```

**Verdict:** ⏳ Pending — confirm invalid/revoked/mismatched sender is rejected before file acceptance and audit line is written.

---

## ⏳ Requirement 5 — Chunked transfer with per-chunk SHA-256 verification

> File must be transferred in chunks; each chunk is individually hashed and verified before writing to the `.part` file.

**Commands:**
```bash
curl -s -X POST http://localhost:8443/api/v1/xfer/send \
  -H "Content-Type: application/json" \
  -d '{
    "peer_did": "<real-peer-did>",
    "path": "<real-10mb-test-file>"
  }' | python3 -m json.tool
```
```bash
curl -s http://localhost:8443/api/v1/xfer/transfers/<transfer_id> | python3 -m json.tool
```

**Result:**
```text
<paste send response here>
<paste progress response here>
```

**Verdict:** ⏳ Pending — confirm chunked send works and progress reflects chunk movement without write-side corruption.

---

## ⏳ Requirement 6 — Resume support via persisted `state.json` / `have_chunks`

> Interrupted transfer must resume by sending only missing chunks, using receiver-side persisted chunk state.

**Commands:**
```bash
curl -s -X POST http://localhost:8443/api/v1/xfer/send \
  -H "Content-Type: application/json" \
  -d '{
    "peer_did": "<real-peer-did>",
    "path": "<real-large-test-file>"
  }' | python3 -m json.tool
```
```bash
pkill -f sgx_guardian_client
```
```bash
./sgx_guardian_client nodeB
```
```bash
curl -s -X POST http://localhost:8443/api/v1/xfer/send \
  -H "Content-Type: application/json" \
  -d '{
    "peer_did": "<same-peer-did>",
    "path": "<same-large-test-file>"
  }' | python3 -m json.tool
```
```bash
cat /var/lib/sgx-guardian/xfer/inbox/<circle_id>/<transfer_id>/state.json | python3 -m json.tool
```

**Result:**
```text
<paste first run result here>
<paste resumed run result here>
<paste state.json here>
```

**Verdict:** ⏳ Pending — confirm persisted chunk bitmap survives restart and resumed send skips already received chunks.

---

## ⏳ Requirement 7 — Whole-file SHA-256 verification and atomic inbox publish

> After all chunks arrive, receiver must verify whole-file SHA-256 and atomically rename `.part` into the final inbox file.

**Commands:**
```bash
sha256sum <sender-file-path>
```
```bash
sha256sum /var/lib/sgx-guardian/xfer/inbox/<circle_id>/<transfer_id>/<filename>
```
```bash
ls -lah /var/lib/sgx-guardian/xfer/inbox/<circle_id>/<transfer_id>/
```

**Result:**
```text
<paste sender hash here>
<paste receiver hash here>
<paste inbox listing here>
```

**Verdict:** ⏳ Pending — confirm sender and receiver hashes match exactly and final file is published without exposing a half-written file.

---

## ⏳ Requirement 8 — Audit trail and transfer progress observability

> Transfer engine must produce audit events and maintain observable transfer progress/status.

**Commands:**
```bash
curl -s http://localhost:8443/api/v1/xfer/transfers | python3 -m json.tool
```
```bash
grep -i xfer /var/log/sgx-guardian/*.log
```

**Result:**
```text
<paste transfers list here>
<paste audit/log output here>
```

**Verdict:** ⏳ Pending — confirm transfer list, per-transfer status, and audit lines are available for send/receive/fail/cancel paths.

---

## 🔌 API Verification

### ⏳ API 1 — POST `/api/v1/xfer/send`

**Command:**
```bash
curl -s -X POST http://localhost:8443/api/v1/xfer/send \
  -H "Content-Type: application/json" \
  -d '{
    "peer_did": "<real-peer-did>",
    "path": "<real-file-path>"
  }' | python3 -m json.tool
```

**Result:**
```json
<paste JSON response here>
```

**Verdict:** ⏳ Pending — confirm API returns accepted response with a fresh `transfer_id`.

---

### ⏳ API 2 — GET `/api/v1/xfer/transfers`

**Command:**
```bash
curl -s http://localhost:8443/api/v1/xfer/transfers | python3 -m json.tool
```

**Result:**
```json
<paste JSON response here>
```

**Verdict:** ⏳ Pending — confirm API lists transfers with direction, status, chunk progress, and timestamps.

---

### ⏳ API 3 — GET `/api/v1/xfer/transfers/{id}`

**Command:**
```bash
curl -s http://localhost:8443/api/v1/xfer/transfers/<transfer_id> | python3 -m json.tool
```

**Result:**
```json
<paste JSON response here>
```

**Verdict:** ⏳ Pending — confirm API returns detail for the current transfer id and reflects live state.

---

### ⏳ API 4 — POST `/api/v1/xfer/transfers/{id}/cancel`

**Command:**
```bash
curl -s -X POST http://localhost:8443/api/v1/xfer/transfers/<transfer_id>/cancel | python3 -m json.tool
```

**Result:**
```json
<paste JSON response here>
```

**Verdict:** ⏳ Pending — confirm API marks transfer cancelled and cleanup/status update is visible afterward.

---

### ⏳ API 5 — GET `/api/v1/xfer/inbox`

**Command:**
```bash
curl -s http://localhost:8443/api/v1/xfer/inbox | python3 -m json.tool
```

**Result:**
```json
<paste JSON response here>
```

**Verdict:** ⏳ Pending — confirm completed received files appear in inbox listing with final path and metadata.

---

## ⚙️ Known Setup Notes

- Guardian REST API port: **8443**
- XFER listener port: **50064**
- XFER storage base: `/var/lib/sgx-guardian/xfer`
- Receiver state path pattern: `/var/lib/sgx-guardian/xfer/inbox/<circle_id>/<transfer_id>/state.json`
- Sender progress path pattern: `/var/lib/sgx-guardian/xfer/outbox/<transfer_id>.json`
- Completed inbox file pattern: `/var/lib/sgx-guardian/xfer/inbox/<circle_id>/<transfer_id>/<filename>`
- Peer DID must already exist in local DID peer docs and must not be revoked

---

## 🛠️ Updates Needed (Improvements Suggested During Testing)

- **R1 —**
  - Observation:
  - Likely code area:
  - Suggested fix:

- **R2 —**
  - Observation:
  - Likely code area:
  - Suggested fix:
