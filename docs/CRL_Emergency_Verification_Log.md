# CRL Emergency Revocation — Verification Log
**Board:** iMX8MP (ARM64) | **Branch:** `<fill-branch>` | **Tester:** `<fill-tester>`

---

## 📌 Task Description

> **CRL Gossip — Emergency Revocation**
>
> Implement priority emergency broadcast channel for critical revocations (compromised devices, active attacks). When Guardian marked `severity: critical`, immediately broadcast `REVOCATION_NOTICE` to all connected peers, bypassing normal gossip intervals. Receiving Guardians prioritize forwarding emergency revocations before routine gossip. Terminate all active sessions with revoked DID instantly. Send push notifications to users. Emergency revocations propagate to 90%+ of Circle within 30 seconds vs 5-10 minutes for normal gossip. Essential for containing active breaches.

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
   - Kya required Guardian processes teenon nodes par chal rahe hain?
   - Kya emergency test ke liye real full DID use hui hai?
   - Kya test ke time peer DID docs / overlay connectivity available thi?
2. **Sirf tab `❌` lagao** jab fully confirm ho jaye ke issue code side ka hai, command side ka nahi
3. **`❌` lagane ke saath ye bhi likho:**
   - Konsi file/function mein likely issue hai
   - Exact error message jo aaya
   - Kya try kiya aur kya nahi chala

**⚠️ Common mistakes jo dobara na karein:**
- **DID hamesha poora `did:guardian:...` prefix ke sath likhna**
- **`<...>` angle brackets literally shell mein mat likhna** — ye sirf template placeholders hain
- **Critical revoke test ke liye `--severity critical` zaroor dena** — warna emergency path intentionally fire nahi karega
- **Non-critical negative test mein counters compare karna** — sirf revoke PASS hona emergency PASS nahi hota
- **Session termination test se pehle واقعی active CoT session establish karna**
- **Notification test mein feed file ya endpoint dono mein se kam az kam ek durable artifact verify karna**

**Symbols:**
- `✅` = Verified and passed
- `❌` = Confirmed code-side failure
- `⏳` = Not yet tested

---

## 🧾 Test Session Details

- **nodeA IP:** `<fill>`
- **nodeB IP:** `<fill>`
- **nodeC IP:** `<fill>`
- **nodeA DID:** `<fill>`
- **nodeB DID:** `<fill>`
- **nodeC DID:** `<fill>`
- **Emergency Port:** `50064`
- **Routine Gossip Port:** `50063`
- **REST Port:** `8443`
- **Emergency Enabled Env:** `<fill current value>`
- **Emergency TTL Env:** `<fill current value>`

---

## 📊 Requirements Checklist (8 Requirements)

- [ ] Requirement 1 — Emergency UDP listener on port `50064` with env gating
- [ ] Requirement 2 — Critical local revoke triggers immediate one-to-many emergency broadcast
- [ ] Requirement 3 — Receiving Guardian re-verifies and merges notice through the existing locked CRL path
- [ ] Requirement 4 — Receiver re-broadcast is bounded by TTL and fingerprint dedup
- [ ] Requirement 5 — Critical revoke terminates active CoT sessions for the revoked DID
- [ ] Requirement 6 — Durable emergency notification feed is recorded for frontend/mobile push
- [ ] Requirement 7 — Emergency observability and manual rebroadcast endpoints work
- [ ] Requirement 8 — Emergency path coexists with routine gossip and enforcement; Merkle roots still converge

---

## 📊 API Checklist (4 APIs)

- [ ] API 1 — POST `/api/v1/crl/revoke` *(critical path triggers emergency broadcast)*
- [ ] API 2 — GET `/api/v1/crl/emergency/status`
- [ ] API 3 — POST `/api/v1/crl/emergency/broadcast?did=`
- [ ] API 4 — GET `/api/v1/crl/emergency/notifications`

---

## 🖥️ CLI / Runtime Hooks Checklist (2 Hooks)

- [ ] Hook 1 — `sgx-pa-cli crl revoke --severity critical` sends emergency broadcast
- [ ] Hook 2 — `SGX_CRL_EMERGENCY_ENABLED=0` disables listener/broadcast path cleanly

---

## ⏳ CRL-022 — Emergency listener starts on UDP 50064 and status reports enabled config

> Verify that the emergency channel is running, configured, and observable on the node.

**Commands:**
```bash
curl -s http://localhost:8443/api/v1/crl/emergency/status | python3 -m json.tool
grep -n "50064" src/enforcement/executor.rs
# optional runtime-log check:
# grep -n "CRL-EMERGENCY listener on 0.0.0.0:50064" <node-log-file>
```

**Result:**
```text
<paste output here>
```

**Verdict:** ⏳ Not yet tested — `<fill after run>`

---

## ⏳ CRL-023 — Critical CLI revoke triggers immediate emergency broadcast

> Verify that a critical revoke issued through `sgx-pa-cli` reaches peers immediately, before waiting for normal gossip intervals.

**Commands:**
```bash
# nodeA
./sgx-pa-cli crl revoke --did did:guardian:test-emergency-cli-001 --reason compromised --severity critical --note "CRL-023"

# nodeB / nodeC
./sgx-pa-cli crl check --did did:guardian:test-emergency-cli-001
curl -s http://localhost:8443/api/v1/crl/emergency/status | python3 -m json.tool
```

**Result:**
```text
<paste output here>
```

**Verdict:** ⏳ Not yet tested — `<fill after run>`

---

## ⏳ CRL-024 — Critical REST revoke triggers immediate emergency broadcast

> Verify that a critical revoke issued through REST also dispatches the emergency path.

**Commands:**
```bash
curl -s -X POST http://localhost:8443/api/v1/crl/revoke \
  -H 'Content-Type: application/json' \
  -d '{"did":"did:guardian:test-emergency-rest-001","reason":"compromised","severity":"critical","note":"CRL-024"}' \
  | python3 -m json.tool

./sgx-pa-cli crl check --did did:guardian:test-emergency-rest-001
curl -s http://localhost:8443/api/v1/crl/emergency/status | python3 -m json.tool
```

**Result:**
```text
<paste output here>
```

**Verdict:** ⏳ Not yet tested — `<fill after run>`

---

## ⏳ CRL-025 — Non-critical revoke does not use emergency channel

> Verify that `high` / `medium` / `low` severity revocations stay on the routine path and do not increment emergency counters.

**Commands:**
```bash
curl -s http://localhost:8443/api/v1/crl/emergency/status | python3 -m json.tool
./sgx-pa-cli crl revoke --did did:guardian:test-emergency-negative-001 --reason policy_violation --severity medium --note "CRL-025"
curl -s http://localhost:8443/api/v1/crl/emergency/status | python3 -m json.tool
```

**Result:**
```text
<paste counter-before and counter-after here>
```

**Verdict:** ⏳ Not yet tested — `<fill after run>`

---

## ⏳ CRL-026 — Receiver verifies signed notice and merges into local CRL

> Verify that the receiving node accepts a valid notice, merges it, and exposes the revoked DID locally.

**Commands:**
```bash
# nodeA
./sgx-pa-cli crl revoke --did did:guardian:test-merge-001 --reason compromised --severity critical --note "CRL-026"

# nodeB
./sgx-pa-cli crl check --did did:guardian:test-merge-001
./sgx-pa-cli crl root
```

**Result:**
```text
<paste output here>
```

**Verdict:** ⏳ Not yet tested — `<fill after run>`

---

## ⏳ CRL-027 — Invalid or tampered emergency notice is rejected

> Verify that a forged / tampered emergency notice does not merge into the local CRL and is rejected by verification.

**Commands:**
```bash
# Suggested approach:
# 1. Capture or construct a notice payload
# 2. Tamper one signed field without re-signing
# 3. Send the UDP datagram to port 50064 on the target node
# 4. Confirm target CRL and counters did not accept it

<insert exact tampered-notice injection command(s) here>
```

**Result:**
```text
<paste output here>
```

**Verdict:** ⏳ Not yet tested — `<fill after run>`

---

## ⏳ CRL-028 — Re-broadcast is bounded by TTL and dedup

> Verify that a received critical notice is forwarded once according to TTL, and duplicate delivery does not cause repeated merges or infinite echo.

**Commands:**
```bash
curl -s http://localhost:8443/api/v1/crl/emergency/status | python3 -m json.tool
# run one fresh critical emergency propagation event
./sgx-pa-cli crl revoke --did did:guardian:test-ttl-001 --reason compromised --severity critical --note "CRL-028"
curl -s http://localhost:8443/api/v1/crl/emergency/status | python3 -m json.tool
```

**Result:**
```text
<paste output here>
```

**Verdict:** ⏳ Not yet tested — `<fill after run>`

---

## ⏳ CRL-029 — Critical revoke terminates active CoT sessions

> Verify that when the revoked DID maps to a live CoT peer session, that session is dropped immediately.

**Commands:**
```bash
# 1. Establish an active CoT session between peers
# 2. Confirm session exists
# 3. Revoke the peer DID with severity=critical
# 4. Confirm the session is gone

<insert exact session-establish / status / revoke / re-check commands here>
```

**Result:**
```text
<paste output here>
```

**Verdict:** ⏳ Not yet tested — `<fill after run>`

---

## ⏳ CRL-030 — Durable emergency notification feed is recorded

> Verify that a critical revocation creates a durable notification record for frontend/mobile polling.

**Commands:**
```bash
curl -s http://localhost:8443/api/v1/crl/emergency/notifications | python3 -m json.tool
# optional file-level check:
# cat /var/lib/sgx-guardian/identity/crl/emergency_notifications.jsonl
```

**Result:**
```text
<paste output here>
```

**Verdict:** ⏳ Not yet tested — `<fill after run>`

---

## ⏳ CRL-031 — GET /api/v1/crl/emergency/status exposes counters and last_notice

> Verify the observability endpoint returns the emergency config, counters, and last notice details.

**Commands:**
```bash
curl -s http://localhost:8443/api/v1/crl/emergency/status | python3 -m json.tool
```

**Result:**
```text
<paste output here>
```

**Verdict:** ⏳ Not yet tested — `<fill after run>`

---

## ⏳ CRL-032 — POST /api/v1/crl/emergency/broadcast re-broadcasts an existing critical entry

> Verify that the manual hook re-sends an already-existing critical revocation without creating a new entry.

**Commands:**
```bash
curl -s -X POST "http://localhost:8443/api/v1/crl/emergency/broadcast?did=did:guardian:test-emergency-cli-001" \
  | python3 -m json.tool

curl -s http://localhost:8443/api/v1/crl/emergency/status | python3 -m json.tool
```

**Result:**
```text
<paste output here>
```

**Verdict:** ⏳ Not yet tested — `<fill after run>`

---

## ⏳ CRL-033 — UDP 50064 is allowed by enforcement and emergency path survives firewall policy

> Verify the ruleset includes the emergency port and emergency propagation still works when enforcement is active.

**Commands:**
```bash
grep -n "50063\\|50064" src/enforcement/executor.rs
# optional runtime nftables check, if used in your board workflow:
# <insert exact board-safe ruleset inspection command here>
```

**Result:**
```text
<paste output here>
```

**Verdict:** ⏳ Not yet tested — `<fill after run>`

---

## ⏳ CRL-034 — Emergency path preserves root convergence with routine gossip

> Verify that after emergency propagation, nodes still converge to the same CRL Merkle root and sequence through the shared merge path.

**Commands:**
```bash
# nodeA / nodeB / nodeC
./sgx-pa-cli crl root
curl -s http://localhost:8443/api/v1/crl/gossip/status | python3 -m json.tool
```

**Result:**
```text
<paste roots / sequences from all nodes here>
```

**Verdict:** ⏳ Not yet tested — `<fill after run>`

---

## 📝 Notes / Issues Found During Verification

```text
<write any anomalies, retries, timing notes, or code-side failures here>
```

---

## ✅ Final Summary

- **Requirements Passed:** `<fill>`
- **APIs Passed:** `<fill>`
- **CLI / Runtime Hooks Passed:** `<fill>`
- **Overall Verdict:** ⏳ `<fill after full verification>`

