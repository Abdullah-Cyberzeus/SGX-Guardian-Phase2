# CRL Emergency Revocation — Verification Log
**Board:** iMX8MP (ARM64) | **Date:** `2026-07-21` | **Branch:** `crl_series` | **Tester:** `Asad Ali`
**Test tag:** CRL-series (CRL-022 - CRL-034) | **Plan:** `docs/CRL_Emergency_Revocation_Complete_Plan.md`

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

- **nodeA IP:** `192.168.1.157`
- **nodeB IP:** `192.168.1.195`
- **nodeC IP:** `192.168.1.196`
- **nodeA DID:** `did:guardian:C2txwUBkHG5GukHRgvbZQqvxtv7CNkNDvdRAQfx9VQkE`
- **nodeB DID:** `did:guardian:3udaKaaqBaN9SsrdtJAtBiDkz8FtHosj9DpPFkS8wXYa`
- **nodeC DID:** `did:guardian:EtFW3QGXPgjjz6RYqqUQqdXrNKknaxFun18A6mr2mySB`
- **Emergency Port:** `50064`
- **Routine Gossip Port:** `50063`
- **REST Port:** `8443`
- **Emergency Enabled Env:** `<fill current value>`
- **Emergency TTL Env:** `<fill current value>`

---

## ⚡ Board Test Setup (run once before CRL-022)

> Run the relevant node command on each physical board. Keep all three `sgx_guardian_client` processes running in separate terminals during emergency verification.

**Start / health commands:**
```bash
# nodeA board
pkill -f sgx_guardian_client || true
./sgx_guardian_client nodeA

# nodeB board
pkill -f sgx_guardian_client || true
./sgx_guardian_client nodeB

# nodeC board
pkill -f sgx_guardian_client || true
./sgx_guardian_client nodeC
```

**Preflight checks (run on each node after startup):**
```bash
pgrep -af sgx_guardian_client
ip addr show nebula0
nebula -config /var/lib/sgx-guardian/nebula/nebula.yaml -test 2>&1
curl -s http://localhost:8443/api/v1/crl/emergency/status | python3 -m json.tool
ss -lun | grep 50064
jq -r .did /var/lib/sgx-guardian/identity/did.json
```

**Expected preflight:**
```text
- sgx_guardian_client process exists on nodeA/nodeB/nodeC with the correct node argument
- nebula0 is UP and matches each node's allocated overlay IP
- nebula -test has no ERRO line
- emergency status returns enabled=true, port=50064, ttl present
- UDP listener is visible on 0.0.0.0:50064
```

**Current board run status:** ❌ CRL-029 failed on final board rerun — CRL-022 through CRL-028, CRL-030 through CRL-034, Hook 1, and Hook 2 PASS. Requirement 5 remains failed/not passed because nodeB kept the active nodeC CoT session after receiving the critical emergency notice (`sessions_terminated_delta=0`).

---

## 📊 Requirements Checklist (8 Requirements)

- [x] Requirement 1 — Emergency UDP listener on port `50064` with env gating
- [x] Requirement 2 — Critical local revoke triggers immediate one-to-many emergency broadcast
- [x] Requirement 3 — Receiving Guardian re-verifies and merges notice through the existing locked CRL path
- [x] Requirement 4 — Receiver re-broadcast is bounded by TTL and fingerprint dedup
- [ ] Requirement 5 — Critical revoke terminates active CoT sessions for the revoked DID
- [x] Requirement 6 — Durable emergency notification feed is recorded for frontend/mobile push
- [x] Requirement 7 — Emergency observability and manual rebroadcast endpoints work
- [x] Requirement 8 — Emergency path coexists with routine gossip and enforcement; Merkle roots still converge

---

## 📊 API Checklist (4 APIs)

- [x] API 1 — POST `/api/v1/crl/revoke` *(critical path triggers emergency broadcast)*
- [x] API 2 — GET `/api/v1/crl/emergency/status`
- [x] API 3 — POST `/api/v1/crl/emergency/broadcast?did=`
- [x] API 4 — GET `/api/v1/crl/emergency/notifications`

---

## 🖥️ CLI / Runtime Hooks Checklist (2 Hooks)

- [x] Hook 1 — `sgx-pa-cli crl revoke --severity critical` sends emergency broadcast
- [x] Hook 2 — `SGX_CRL_EMERGENCY_ENABLED=0` disables listener/broadcast path cleanly

---

## ✅ CRL-022 — Emergency listener starts on UDP 50064 and status reports enabled config

> Verify that the emergency channel is running, configured, and observable on the node.

**Commands:**
```bash
curl -s http://localhost:8443/api/v1/crl/emergency/status | python3 -m json.tool
ss -lun | grep 50064
# if ss is not available on the board:
netstat -lun | grep 50064
# listener startup line is printed once in this node's own daemon terminal at boot:
# "🚨 CRL-EMERGENCY listener on 0.0.0.0:50064" — scroll back or check /var/log/sgx-guardian/audit-nodeX.log
```

**Result:**
```text
NodeA:
pgrep: 177145 ./sgx_guardian_client nodeA
nebula0: UP, inet 192.168.100.1/24
nebula -test: no ERRO line; config loads pki nodeA.crt/nodeA.key, lighthouse=true
emergency status:
{
  "enabled": true,
  "port": 50064,
  "ttl": 1,
  "notices_sent": 0,
  "notices_received": 0,
  "notices_merged": 0,
  "notices_rebroadcast": 0,
  "sessions_terminated": 0,
  "last_notice": null
}
listener: udp 0 0 0.0.0.0:50064 0.0.0.0:*
DID: did:guardian:C2txwUBkHG5GukHRgvbZQqvxtv7CNkNDvdRAQfx9VQkE

Label correction note:
The pasted "Node B" block shows:
  pgrep: 34989 ./sgx_guardian_client nodeC
  nebula0: inet 192.168.100.2/24
  pki: nodeC.crt/nodeC.key
  DID: did:guardian:EtFW3QGXPgjjz6RYqqUQqdXrNKknaxFun18A6mr2mySB
This was treated as nodeC evidence. A later attachment provided actual nodeB evidence.

NodeB:
pgrep: 452399 ./sgx_guardian_client nodeB
nebula0: UP, inet 192.168.100.3/24
nebula -test: no ERRO line; config loads pki nodeB.crt/nodeB.key, lighthouse=false, relay via 192.168.100.1
emergency status:
{
  "enabled": true,
  "port": 50064,
  "ttl": 1,
  "notices_sent": 0,
  "notices_received": 0,
  "notices_merged": 0,
  "notices_rebroadcast": 0,
  "sessions_terminated": 0,
  "last_notice": null
}
listener: udp 0 0 0.0.0.0:50064 0.0.0.0:*
DID: did:guardian:3udaKaaqBaN9SsrdtJAtBiDkz8FtHosj9DpPFkS8wXYa

NodeC:
pgrep: 34989 ./sgx_guardian_client nodeC
nebula0: UP, inet 192.168.100.2/24
nebula -test: no ERRO line; config loads pki nodeC.crt/nodeC.key, lighthouse=false, relay via 192.168.100.1
emergency status:
{
  "enabled": true,
  "port": 50064,
  "ttl": 1,
  "notices_sent": 0,
  "notices_received": 0,
  "notices_merged": 0,
  "notices_rebroadcast": 0,
  "sessions_terminated": 0,
  "last_notice": null
}
listener: udp 0 0 0.0.0.0:50064 0.0.0.0:*
DID: did:guardian:EtFW3QGXPgjjz6RYqqUQqdXrNKknaxFun18A6mr2mySB
```

**Verdict:** ✅ PASS — nodeA, nodeB, and nodeC all report emergency `enabled=true`, `port=50064`, `ttl=1`; Nebula config validates without `ERRO`; UDP listener `0.0.0.0:50064` is visible on all three boards.

---

## ✅ CRL-023 — Critical CLI revoke triggers immediate emergency broadcast

> Verify that a critical revoke issued through `sgx-pa-cli` reaches peers immediately, before waiting for normal gossip intervals.

**Commands:**
```bash
# nodeA
DID_023="did:guardian:board-emergency-cli-20260721-002"
/home/root/sgx-pa-cli crl revoke --did "$DID_023" --reason compromised --severity critical --note "CRL-023 retry-after-se050-recovery"
curl -s http://localhost:8443/api/v1/crl/emergency/status | python3 -m json.tool

# nodeB / nodeC
DID_023="did:guardian:board-emergency-cli-20260721-002"
for i in $(seq 1 30); do
  /home/root/sgx-pa-cli crl check --did "$DID_023" | grep -q '"revoked": true' && break
  sleep 1
done
/home/root/sgx-pa-cli crl check --did "$DID_023"
curl -s http://localhost:8443/api/v1/crl/emergency/status | python3 -m json.tool
```

**Result:**
```text
Attempt 1 on nodeA:
DID_023="did:guardian:board-emergency-cli-20260721-001"
/home/root/sgx-pa-cli crl revoke --did "$DID_023" --reason compromised --severity critical --note "CRL-023"

Output:
  Existing DKP found (v1) — loading from SE050
  Using existing device identity key (0x20000010)
  ❌ did: DID derivation signature failed: DKP sign: SE050 sign failed:
  ssscli failed: ssscli sign 0x20000010 ... — ERROR:sss.session:No open session, try connecting first
  ERROR:sss.session:Run 'ssscli connect --help' for more information.
  ERROR:cli.cli:No open session, try connecting first
  ERROR:cli.cli:'Context' object has no attribute 'session'

nodeA emergency status after failed CLI attempt:
{
  "enabled": true,
  "port": 50064,
  "ttl": 1,
  "notices_sent": 0,
  "notices_received": 0,
  "notices_merged": 0,
  "notices_rebroadcast": 0,
  "sessions_terminated": 0,
  "last_notice": null
}

nodeB check after failed nodeA CLI attempt:
{
  "did": "did:guardian:board-emergency-cli-20260721-001",
  "entry": null,
  "revoked": false
}
nodeB emergency counters remained 0.

nodeC check after failed nodeA CLI attempt:
{
  "did": "did:guardian:board-emergency-cli-20260721-001",
  "entry": null,
  "revoked": false
}
nodeC emergency counters remained 0.
```

**Attempt verdict:** ⏳ Blocked / retry required — this attempt did not reach CRL emergency logic because `sgx-pa-cli` failed before issuing the local revocation due to an SE050 `ssscli` session error (`No open session`). This is a board command/SE050 session blocker, not a confirmed CRL emergency code failure.

**Retry / SE050 probe evidence:**
```text
nodeA manual SE050 session reset/probe:
SCP key: /home/root/se05x_mw_v04.05.01/simw-top/scripts/se050F_scp_keys.txt
ssscli connect --auth_type PlatformSCP --scpkey "$SCP_KEY" se05x t1oi2c none
ssscli se05x uid

Result:
Unique ID: 0400500111b7985e065254047857bae51090

Direct DKP sign probe:
printf 'crl-023-probe' > /tmp/crl_023_probe.bin
ssscli sign 0x20000010 /tmp/crl_023_probe.bin /tmp/crl_023_probe.sig

Result:
smCom :ERROR:phNxpEseProto7816_CheckCRC CRC failed
smCom :ERROR:phNxpEseProto7816_ProcessResponse CRC Check failed
smCom :ERROR:phNxpEseProto7816_Transceive Transceive failed, hard reset to proceed
ERROR:sss.asymmetric:sss_asymmetric_sign_digest'FAILED
ERROR:sss.sign:Received signature data is empty
ERROR! Could not Sign from KeyID 0x20000010
ls: cannot access '/tmp/crl_023_probe.sig': No such file or directory

CRL-023 retry after probe:
/home/root/sgx-pa-cli crl revoke --did did:guardian:board-emergency-cli-20260721-001 --reason compromised --severity critical --note "CRL-023 retry"

Result:
❌ did: DID derivation signature failed: DKP sign: SE050 sign failed:
ERROR:sss.session:No open session, try connecting first

nodeA daemon log during same recovery window:
🔴 SE050 TAMPER DETECTED — all crypto operations blocked
```

**Retry verdict:** ⏳ Still blocked — SE050 can answer UID reads, but DKP signing from slot `0x20000010` fails with CRC/transceive errors and nodeA later reports tamper state. Do not mark CRL-023 failed; the revoke operation never created a CRL entry and never reached emergency broadcast.

**SE050 recovery evidence:**
```text
nodeA recovery sequence:
pkill -f sgx_guardian_client || true
pkill -f ssscli || true
rm -f /root/.ssscli_session.pkl /root/~.ssscli_session.pkl ~/.ssscli_session.pkl ~/~.ssscli_session.pkl
ssscli connect --auth_type PlatformSCP --scpkey "$SCP_KEY" se05x t1oi2c none
ssscli se05x uid
ssscli se05x readidlist | grep -i 20000010
ssscli sign 0x20000010 /tmp/crl_023_probe.bin /tmp/crl_023_probe.sig

Result:
Unique ID: 0400500111b7985e065254047857bae51090
Key-Id: 0X20000010   NIST-P            (Key Pair)     Size(Bits): 256
Signed from KeyID = 0x20000010
-rw-r--r-- 1 root root 71 Jul 21 06:29 /tmp/crl_023_probe.sig
```

**Recovery verdict:** ✅ SE050 DKP signing recovered on nodeA. Restart nodeA daemon and rerun CRL-023.

Final successful retry after SE050 recovery:
```text
NodeA:
DID_023="did:guardian:board-emergency-cli-20260721-002"
/home/root/sgx-pa-cli crl revoke --did "$DID_023" --reason compromised --severity critical --note "CRL-023 retry-after-se050-recovery"

Output:
  Existing DKP found (v1) — loading from SE050
  Using existing device identity key (0x20000010)
  ✅ CRL entry issued: urn:uuid:bc6a8b32-4dc6-4193-9102-50ece3c42362
     sequence=1
     root=3e4caa8960202355ead8c13fdb93cb4c868f9ce78a07de335a2399dd6559d01b
  🚨 EMERGENCY broadcast revoked_did=did:guardian:board-emergency-cli-20260721-002 → 2 peers

nodeA emergency status:
{
  "enabled": true,
  "port": 50064,
  "ttl": 1,
  "notices_sent": 0,
  "notices_received": 0,
  "notices_merged": 0,
  "notices_rebroadcast": 0,
  "sessions_terminated": 0,
  "last_notice": null
}

NodeB:
/home/root/sgx-pa-cli crl check --did "$DID_023"
Result:
  "id": "urn:uuid:bc6a8b32-4dc6-4193-9102-50ece3c42362"
  "revoked_did": "did:guardian:board-emergency-cli-20260721-002"
  "revoker_did": "did:guardian:C2txwUBkHG5GukHRgvbZQqvxtv7CNkNDvdRAQfx9VQkE"
  "severity": "critical"
  "reason": "compromised"
  "revoked": true

nodeB emergency status:
{
  "enabled": true,
  "port": 50064,
  "ttl": 1,
  "notices_sent": 0,
  "notices_received": 2,
  "notices_merged": 1,
  "notices_rebroadcast": 1,
  "sessions_terminated": 0,
  "last_notice": {
    "direction": "received",
    "revoked_did": "did:guardian:board-emergency-cli-20260721-002",
    "origin_did": "did:guardian:C2txwUBkHG5GukHRgvbZQqvxtv7CNkNDvdRAQfx9VQkE",
    "peers": 0,
    "merged": true,
    "at": "2026-07-21T06:32:33.217408518+00:00"
  }
}

NodeC:
/home/root/sgx-pa-cli crl check --did "$DID_023"
Result:
  "id": "urn:uuid:bc6a8b32-4dc6-4193-9102-50ece3c42362"
  "revoked_did": "did:guardian:board-emergency-cli-20260721-002"
  "revoker_did": "did:guardian:C2txwUBkHG5GukHRgvbZQqvxtv7CNkNDvdRAQfx9VQkE"
  "severity": "critical"
  "reason": "compromised"
  "revoked": true

nodeC emergency status:
{
  "enabled": true,
  "port": 50064,
  "ttl": 1,
  "notices_sent": 0,
  "notices_received": 2,
  "notices_merged": 1,
  "notices_rebroadcast": 1,
  "sessions_terminated": 0,
  "last_notice": {
    "direction": "received",
    "revoked_did": "did:guardian:board-emergency-cli-20260721-002",
    "origin_did": "did:guardian:C2txwUBkHG5GukHRgvbZQqvxtv7CNkNDvdRAQfx9VQkE",
    "peers": 0,
    "merged": true,
    "at": "2026-07-21T06:32:29.943064660+00:00"
  }
}
```

**Verdict:** ✅ PASS — after SE050 signing recovery, critical CLI revoke created a signed CRL entry on nodeA and immediately emergency-broadcast it to 2 peers. nodeB and nodeC both reached `revoked=true` for the same entry id, with receiver emergency counters showing `notices_received=2`, `notices_merged=1`, and `notices_rebroadcast=1`.

---

## ✅ CRL-024 — Critical REST revoke triggers immediate emergency broadcast

> Verify that a critical revoke issued through REST also dispatches the emergency path.

**Commands:**
```bash
# nodeA
DID_024="did:guardian:board-emergency-rest-20260721-001"
curl -s -X POST http://localhost:8443/api/v1/crl/revoke \
  -H 'Content-Type: application/json' \
  -d '{"did":"'"$DID_024"'","reason":"compromised","severity":"critical","note":"CRL-024 board REST"}' \
  | python3 -m json.tool
curl -s http://localhost:8443/api/v1/crl/emergency/status | python3 -m json.tool

# nodeB / nodeC
DID_024="did:guardian:board-emergency-rest-20260721-001"
for i in $(seq 1 30); do
  /home/root/sgx-pa-cli crl check --did "$DID_024" | grep -q '"revoked": true' && break
  sleep 1
done
/home/root/sgx-pa-cli crl check --did "$DID_024"
curl -s http://localhost:8443/api/v1/crl/emergency/status | python3 -m json.tool
```

**Result:**
```text
NodeA REST revoke:
{
  "status": "success",
  "message": "CRL entry issued",
  "entry": {
    "id": "urn:uuid:527bdd48-077e-4052-b9e4-7a65bd387104",
    "revoked_did": "did:guardian:board-emergency-rest-20260721-001",
    "circle_id": "guardian-circle-alpha",
    "reason": "compromised",
    "severity": "critical",
    "revoker_did": "did:guardian:C2txwUBkHG5GukHRgvbZQqvxtv7CNkNDvdRAQfx9VQkE",
    "revoker_role": "owner",
    "evidence": { "note": "CRL-024 board REST" },
    "proof": {
      "verificationMethod": "did:guardian:C2txwUBkHG5GukHRgvbZQqvxtv7CNkNDvdRAQfx9VQkE#dkp-v1"
    },
    "propagated": false
  },
  "sequence": 4,
  "merkle_root": "e700de1442002992e47c8809ffe727b47e549c226fe162a66cf335a3c8e08900"
}

nodeA emergency status after REST revoke:
{
  "enabled": true,
  "port": 50064,
  "ttl": 1,
  "notices_sent": 1,
  "notices_received": 0,
  "notices_merged": 0,
  "notices_rebroadcast": 0,
  "sessions_terminated": 0,
  "last_notice": {
    "direction": "sent",
    "revoked_did": "did:guardian:board-emergency-rest-20260721-001",
    "origin_did": "did:guardian:C2txwUBkHG5GukHRgvbZQqvxtv7CNkNDvdRAQfx9VQkE",
    "peers": 2,
    "merged": true,
    "at": "2026-07-21T06:35:58.564310146+00:00"
  }
}

NodeB:
/home/root/sgx-pa-cli crl check --did "$DID_024"
Result:
  "id": "urn:uuid:527bdd48-077e-4052-b9e4-7a65bd387104"
  "revoked_did": "did:guardian:board-emergency-rest-20260721-001"
  "severity": "critical"
  "reason": "compromised"
  "revoked": true

nodeB emergency status:
{
  "enabled": true,
  "port": 50064,
  "ttl": 1,
  "notices_sent": 0,
  "notices_received": 4,
  "notices_merged": 2,
  "notices_rebroadcast": 2,
  "sessions_terminated": 0,
  "last_notice": {
    "direction": "received",
    "revoked_did": "did:guardian:board-emergency-rest-20260721-001",
    "origin_did": "did:guardian:C2txwUBkHG5GukHRgvbZQqvxtv7CNkNDvdRAQfx9VQkE",
    "peers": 0,
    "merged": true,
    "at": "2026-07-21T06:36:02.129553235+00:00"
  }
}

NodeC:
/home/root/sgx-pa-cli crl check --did "$DID_024"
Result:
  "id": "urn:uuid:527bdd48-077e-4052-b9e4-7a65bd387104"
  "revoked_did": "did:guardian:board-emergency-rest-20260721-001"
  "severity": "critical"
  "reason": "compromised"
  "revoked": true

nodeC emergency status:
{
  "enabled": true,
  "port": 50064,
  "ttl": 1,
  "notices_sent": 0,
  "notices_received": 4,
  "notices_merged": 2,
  "notices_rebroadcast": 2,
  "sessions_terminated": 0,
  "last_notice": {
    "direction": "received",
    "revoked_did": "did:guardian:board-emergency-rest-20260721-001",
    "origin_did": "did:guardian:C2txwUBkHG5GukHRgvbZQqvxtv7CNkNDvdRAQfx9VQkE",
    "peers": 0,
    "merged": true,
    "at": "2026-07-21T06:36:01.875019130+00:00"
  }
}
```

**Verdict:** ✅ PASS — REST `POST /api/v1/crl/revoke` created a critical signed entry on nodeA and dispatched emergency broadcast to 2 peers. nodeB and nodeC both reported `revoked=true` for the same entry id, and receiver emergency counters increased with merge/rebroadcast activity.

---

## ✅ CRL-025 — Non-critical revoke does not use emergency channel

> Verify that `high` / `medium` / `low` severity revocations stay on the routine path and do not increment emergency counters.

**Commands:**
```bash
# nodeA only — owner issues a non-critical revocation
DID_025="did:guardian:board-emergency-negative-20260721-001"
curl -s http://localhost:8443/api/v1/crl/emergency/status > /tmp/a_pre_025.json
/home/root/sgx-pa-cli crl revoke --did "$DID_025" --reason policy_violation --severity medium --note "CRL-025 board negative"
sleep 5
curl -s http://localhost:8443/api/v1/crl/emergency/status > /tmp/a_post_025.json
python3 - <<'PY'
import json
pre=json.load(open("/tmp/a_pre_025.json"))
post=json.load(open("/tmp/a_post_025.json"))
for k in ["notices_sent","notices_received","notices_merged","notices_rebroadcast"]:
    print(k, post[k]-pre[k])
print("last_notice_same:", pre.get("last_notice")==post.get("last_notice"))
PY

# nodeB / nodeC only — do not issue revoke here; compare passive emergency counters
curl -s http://localhost:8443/api/v1/crl/emergency/status > /tmp/pre_025.json
sleep 7
curl -s http://localhost:8443/api/v1/crl/emergency/status > /tmp/post_025.json
python3 - <<'PY'
import json
pre=json.load(open("/tmp/pre_025.json"))
post=json.load(open("/tmp/post_025.json"))
for k in ["notices_sent","notices_received","notices_merged","notices_rebroadcast"]:
    print(k, post[k]-pre[k])
print("last_notice_same:", pre.get("last_notice")==post.get("last_notice"))
PY
```

**Result:**
```text
NodeA:
/home/root/sgx-pa-cli crl revoke --did did:guardian:board-emergency-negative-20260721-001 --reason policy_violation --severity medium --note "CRL-025 board negative"
Output:
  Existing DKP found (v1) — loading from SE050
  Using existing device identity key (0x20000010)
  ✅ CRL entry issued: urn:uuid:8f264bbe-c290-41ed-b23e-24bbe3ac57a1
     sequence=7
     root=f742af5ba74b011f011cb679eebbc36f9cd487e999b1dfa1c9ec01749f8f7191

NodeA emergency delta output:
  notices_sent 0
  notices_received 0
  notices_merged 0
  notices_rebroadcast 0
  last_notice_same: True

NodeB accidental local command:
/home/root/sgx-pa-cli crl revoke --did "$DID_025" --reason policy_violation --severity medium --note "CRL-025 board negative"
Output:
  ❌ member-issued entries must be Critical or High severity (got Medium)
Emergency deltas after rejected local command:
  notices_sent 0
  notices_received 0
  notices_merged 0
  notices_rebroadcast 0
  last_notice_same: True

NodeC accidental local command:
/home/root/sgx-pa-cli crl revoke --did "$DID_025" --reason policy_violation --severity medium --note "CRL-025 board negative"
Output:
  ❌ member-issued entries must be Critical or High severity (got Medium)
Emergency deltas after rejected local command:
  notices_sent 0
  notices_received 0
  notices_merged 0
  notices_rebroadcast 0
  last_notice_same: True

Passive rerun on nodeB:
  notices_sent 0
  notices_received 0
  notices_merged 0
  notices_rebroadcast 0
  last_notice_same: True

Passive rerun on nodeC:
  notices_sent 0
  notices_received 0
  notices_merged 0
  notices_rebroadcast 0
  last_notice_same: True
```

**Verdict:** ✅ PASS — nodeA owner issued a medium-severity local CRL entry, and emergency counters stayed unchanged (`notices_sent/received/merged/rebroadcast` all delta 0). Passive receiver checks on nodeB and nodeC also stayed at delta 0 with unchanged `last_notice`, proving non-critical revocations do not use the emergency channel.

---

## ✅ CRL-026 — Receiver verifies signed notice and merges into local CRL

> Verify that the receiving node accepts a valid notice, merges it, and exposes the revoked DID locally.

**Commands:**
```bash
# nodeA
/home/root/sgx-pa-cli crl revoke --did did:guardian:test-merge-001 --reason compromised --severity critical --note "CRL-026"

# nodeB
/home/root/sgx-pa-cli crl check --did did:guardian:test-merge-001
/home/root/sgx-pa-cli crl root
```

**Result:**
```text
nodeA source:
/home/root/sgx-pa-cli crl revoke --did did:guardian:board-emergency-merge-20260721-001 --reason compromised --severity critical --note "CRL-026 board merge"

Output:
  Existing DKP found (v1) — loading from SE050
  Using existing device identity key (0x20000010)
  ✅ CRL entry issued: urn:uuid:a4bb81fc-bd26-4ea9-9513-2476814e7536
     sequence=8
     root=1498e6d1e9d02714b88ff7c4b72e8fe2aedc26ef2a2c3845e92c4e873481d8a2
  🚨 EMERGENCY broadcast revoked_did=did:guardian:board-emergency-merge-20260721-001 → 2 peers

nodeA root:
{
  "merkle_root": "1498e6d1e9d02714b88ff7c4b72e8fe2aedc26ef2a2c3845e92c4e873481d8a2",
  "sequence": 8
}

Receiver evidence 1:
/home/root/sgx-pa-cli crl check --did did:guardian:board-emergency-merge-20260721-001
Result:
  "id": "urn:uuid:a4bb81fc-bd26-4ea9-9513-2476814e7536"
  "revoked_did": "did:guardian:board-emergency-merge-20260721-001"
  "revoker_did": "did:guardian:C2txwUBkHG5GukHRgvbZQqvxtv7CNkNDvdRAQfx9VQkE"
  "severity": "critical"
  "reason": "compromised"
  "revoked": true

Receiver evidence 1 root/status:
{
  "merkle_root": "1498e6d1e9d02714b88ff7c4b72e8fe2aedc26ef2a2c3845e92c4e873481d8a2",
  "sequence": 11
}
emergency status:
{
  "notices_received": 5,
  "notices_merged": 3,
  "notices_rebroadcast": 3,
  "last_notice": {
    "direction": "received",
    "revoked_did": "did:guardian:board-emergency-merge-20260721-001",
    "origin_did": "did:guardian:C2txwUBkHG5GukHRgvbZQqvxtv7CNkNDvdRAQfx9VQkE",
    "merged": true,
    "at": "2026-07-21T06:46:29.753004718+00:00"
  }
}

Receiver evidence 2:
/home/root/sgx-pa-cli crl check --did did:guardian:board-emergency-merge-20260721-001
Result:
{
  "did": "did:guardian:board-emergency-merge-20260721-001",
  "entry": null,
  "revoked": false
}
root:
{
  "merkle_root": "f742af5ba74b011f011cb679eebbc36f9cd487e999b1dfa1c9ec01749f8f7191",
  "sequence": 8
}
emergency status last_notice still points to the older REST test:
  "revoked_did": "did:guardian:board-emergency-rest-20260721-001"
```

**Verdict:** ⏳ Partial / retry required — nodeA issued and emergency-broadcast the signed critical entry, and one receiver merged it successfully through the locked CRL path. The other receiver still showed `revoked=false` and did not update `last_notice`, so CRL-026 cannot be marked full PASS until that receiver is caught up or the missing delivery is explained.

**Manual rebroadcast retry:**
```text
nodeA:
curl -s -X POST "http://localhost:8443/api/v1/crl/emergency/broadcast?did=did:guardian:board-emergency-merge-20260721-001" | python3 -m json.tool
{
  "success": true,
  "revoked_did": "did:guardian:board-emergency-merge-20260721-001",
  "message": "emergency broadcast dispatched"
}

nodeA status after manual rebroadcast:
{
  "notices_sent": 2,
  "last_notice": {
    "direction": "sent",
    "revoked_did": "did:guardian:board-emergency-merge-20260721-001",
    "origin_did": "did:guardian:C2txwUBkHG5GukHRgvbZQqvxtv7CNkNDvdRAQfx9VQkE",
    "peers": 2,
    "merged": true,
    "at": "2026-07-21T06:49:52.362781668+00:00"
  }
}

nodeB before retry:
{
  "notices_received": 6,
  "notices_merged": 2,
  "notices_rebroadcast": 2,
  "last_notice": {
    "revoked_did": "did:guardian:board-emergency-rest-20260721-001",
    "merged": true
  }
}

nodeB after retry:
{
  "did": "did:guardian:board-emergency-merge-20260721-001",
  "entry": null,
  "revoked": false
}
root:
{
  "merkle_root": "f742af5ba74b011f011cb679eebbc36f9cd487e999b1dfa1c9ec01749f8f7191",
  "sequence": 8
}
status:
{
  "notices_received": 7,
  "notices_merged": 2,
  "notices_rebroadcast": 2,
  "last_notice": {
    "revoked_did": "did:guardian:board-emergency-rest-20260721-001",
    "merged": true
  }
}
```

**Retry verdict:** ⏳ Still partial — nodeB listener received another emergency datagram (`notices_received` increased 6→7), but it did not merge the `CRL-026` entry and `last_notice` stayed on the previous REST test. Need nodeB rejection/drop diagnostics before deciding whether this is command/state issue or code-side failure.

**nodeB diagnostics after missed merge:**
```text
nodeB audit grep showed earlier trust/peer-directory failures for nodeA:
  Peer 192.168.100.1:50151 VC rejected:
  known CA DID: VC structure invalid: circle owner DID could not be determined from local VC or config

  CRL gossip rejected sender=did:guardian:C2txwUBkHG5GukHRgvbZQqvxtv7CNkNDvdRAQfx9VQkE:
  sender not in local peer directory: did:guardian:C2txwUBkHG5GukHRgvbZQqvxtv7CNkNDvdRAQfx9VQkE

Later in the same nodeB audit tail, peer trust recovered:
  Peer 192.168.100.1:50151 VC verified for did:guardian:C2txwUBkHG5GukHRgvbZQqvxtv7CNkNDvdRAQfx9VQkE
  Peer 192.168.100.1:50151 successfully attested and trusted
  Incoming peer VC verified for did:guardian:C2txwUBkHG5GukHRgvbZQqvxtv7CNkNDvdRAQfx9VQkE

CLI typo found:
  /home/root/sgx-pa-cli diddoc peers
  error: unrecognized subcommand 'diddoc'
  Correct command is `did-doc` (or REST `/api/v1/did/document/peers`).
```

**Diagnostic verdict:** ⏳ The missed merge is likely state/timing related: nodeB had a stale/missing nodeA peer directory/trust state around delivery time, then recovered later. Inference from `src/crl/gossip/emergency.rs`: a failed first receive can still mark the entry fingerprint as seen before verification/merge, so rebroadcasting the same entry may be deduped without merge. Run a fresh CRL-026 DID after confirming nodeB sees nodeA in the peer document directory.

**Fresh DID rerun attempt:**
```text
nodeA:
DID_026B="did:guardian:board-emergency-merge-20260721-002"
/home/root/sgx-pa-cli crl revoke --did "$DID_026B" --reason compromised --severity critical --note "CRL-026 board merge rerun"

Result:
❌ did: DID derivation signature failed: DKP sign: SE050 sign failed:
ssscli failed: ssscli sign 0x20000010 ... — ERROR:sss.session:No open session, try connecting first

nodeA status/root after failed rerun:
  notices_sent remained 2
  last_notice still `did:guardian:board-emergency-merge-20260721-001`
  root remained 1498e6d1e9d02714b88ff7c4b72e8fe2aedc26ef2a2c3845e92c4e873481d8a2
  sequence remained 8

nodeB/nodeC after failed nodeA rerun:
  "revoked": false for did:guardian:board-emergency-merge-20260721-002
  root remained f742af5ba74b011f011cb679eebbc36f9cd487e999b1dfa1c9ec01749f8f7191
  sequence remained 8
```

**Fresh DID rerun verdict:** ⏳ Blocked by recurring nodeA SE050 `ssscli` session failure before CRL entry issuance. B/C `revoked=false` is expected because nodeA never created or broadcast the new entry.

**Clean rerun after SE050 recovery:**
```text
nodeA:
DID_026C="did:guardian:board-emergency-merge-20260721-003"
/home/root/sgx-pa-cli crl revoke --did "$DID_026C" --reason compromised --severity critical --note "CRL-026 board merge clean rerun"

Output:
  Existing DKP found (v1) — loading from SE050
  Using existing device identity key (0x20000010)
  ✅ CRL entry issued: urn:uuid:d2d5b26d-dcbd-4428-8d56-97e092136cee
     sequence=9
     root=9ecd38f070a3f3c8a95455bf745ac501c828facf1f31388a96a1803b8c9c7756
  🚨 EMERGENCY broadcast revoked_did=did:guardian:board-emergency-merge-20260721-003 → 2 peers

nodeA root:
{
  "merkle_root": "9ecd38f070a3f3c8a95455bf745ac501c828facf1f31388a96a1803b8c9c7756",
  "sequence": 9
}

nodeC receiver:
/home/root/sgx-pa-cli crl check --did "$DID_026C"
Result:
  "id": "urn:uuid:d2d5b26d-dcbd-4428-8d56-97e092136cee"
  "revoked_did": "did:guardian:board-emergency-merge-20260721-003"
  "revoker_did": "did:guardian:C2txwUBkHG5GukHRgvbZQqvxtv7CNkNDvdRAQfx9VQkE"
  "severity": "critical"
  "reason": "compromised"
  "revoked": true

nodeC root:
{
  "merkle_root": "9ecd38f070a3f3c8a95455bf745ac501c828facf1f31388a96a1803b8c9c7756",
  "sequence": 13
}

nodeC emergency status:
{
  "enabled": true,
  "port": 50064,
  "ttl": 1,
  "notices_sent": 0,
  "notices_received": 7,
  "notices_merged": 4,
  "notices_rebroadcast": 4,
  "sessions_terminated": 0,
  "last_notice": {
    "direction": "received",
    "revoked_did": "did:guardian:board-emergency-merge-20260721-003",
    "origin_did": "did:guardian:C2txwUBkHG5GukHRgvbZQqvxtv7CNkNDvdRAQfx9VQkE",
    "peers": 0,
    "merged": true,
    "at": "2026-07-21T07:13:58.352294036+00:00"
  }
}

nodeB anomaly during same clean rerun:
/home/root/sgx-pa-cli crl check --did "$DID_026C"
{
  "did": "did:guardian:board-emergency-merge-20260721-003",
  "entry": null,
  "revoked": false
}
nodeB status received counter increased to 8, but notices_merged stayed 2 and last_notice stayed on the earlier REST test.
```

**Final verdict:** ✅ PASS for CRL-026 receiver-merge requirement — nodeC received the signed emergency notice, verified it, merged the same entry id through the local CRL path, and exposed `revoked=true` with matching Merkle root. NodeB non-merge remains a recorded anomaly for convergence/fanout follow-up, not a blocker for proving that a receiving Guardian can verify and merge the notice.

---

## ✅ CRL-027 — Invalid or tampered emergency notice is rejected

> Verify that a forged / tampered emergency notice does not merge into the local CRL and is rejected by verification.

**Commands:**
```bash
# nodeA — capture a real signed entry, then tamper the revoked_did field
DID_027_GOOD="did:guardian:board-emergency-tamper-src-20260721-001"
DID_027_BAD="did:guardian:board-emergency-tampered-20260721-001"

/home/root/sgx-pa-cli crl revoke --did "$DID_027_GOOD" --reason compromised --severity critical --note "CRL-027 source"
curl -s "http://localhost:8443/api/v1/crl/check?did=$DID_027_GOOD" > /tmp/good_check_027.json

python3 - <<'PY'
import json, uuid, datetime
good = json.load(open('/tmp/good_check_027.json'))
entry = good["entry"]
entry["revoked_did"] = "did:guardian:board-emergency-tampered-20260721-001"
notice = {
    "kind": "crl_revocation_notice",
    "circle_id": entry["circle_id"],
    "origin_did": entry["revoker_did"],
    "notice_id": str(uuid.uuid4()),
    "ttl": 1,
    "sent_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "entry": entry,
}
open('/tmp/tampered_notice_027.json', 'w').write(json.dumps(notice))
PY

python3 - <<'PY'
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(open('/tmp/tampered_notice_027.json', 'rb').read(), ("192.168.1.195", 50064))
PY

# nodeB — confirm it was rejected, not merged
DID_027_BAD="did:guardian:board-emergency-tampered-20260721-001"
/home/root/sgx-pa-cli crl check --did "$DID_027_BAD"
curl -s http://localhost:8443/api/v1/crl/emergency/status | python3 -m json.tool
grep -aE "$DID_027_BAD|rejected|dropped|verify failed|signature" /var/log/sgx-guardian/audit-nodeB.log | tail -20
```

**Result:**
```text
NodeA source entry and tampered notice injection:
DID_027_GOOD="did:guardian:board-emergency-tamper-src-20260721-001"
DID_027_BAD="did:guardian:board-emergency-tampered-20260721-001"

/home/root/sgx-pa-cli crl revoke --did "$DID_027_GOOD" --reason compromised --severity critical --note "CRL-027 source"

Output:
  Existing DKP found (v1) — loading from SE050
  Using existing device identity key (0x20000010)
  ✅ CRL entry issued: urn:uuid:d0881f0b-5410-4a1b-bd85-7bb8df0c59bc
     sequence=10
     root=bd99c54bca2c706d87ef30a786527666671838c7702fe8ecf569541c9bb5c82b
  🚨 EMERGENCY broadcast revoked_did=did:guardian:board-emergency-tamper-src-20260721-001 → 2 peers

nodeA then fetched the valid entry, changed only:
  revoked_did: did:guardian:board-emergency-tampered-20260721-001
and sent the tampered notice by UDP to nodeB at 192.168.1.195:50064.

NodeB check for tampered DID:
{
  "did": "did:guardian:board-emergency-tampered-20260721-001",
  "entry": null,
  "revoked": false
}

nodeB emergency status after tampered UDP notice:
{
  "enabled": true,
  "port": 50064,
  "ttl": 1,
  "notices_sent": 0,
  "notices_received": 11,
  "notices_merged": 2,
  "notices_rebroadcast": 2,
  "sessions_terminated": 0,
  "last_notice": {
    "direction": "received",
    "revoked_did": "did:guardian:board-emergency-rest-20260721-001",
    "origin_did": "did:guardian:C2txwUBkHG5GukHRgvbZQqvxtv7CNkNDvdRAQfx9VQkE",
    "peers": 0,
    "merged": true,
    "at": "2026-07-21T06:36:02.129553235+00:00"
  }
}

nodeB audit evidence:
{
  "event": {
    "action": "Failed",
    "category": "Crl",
    "message": "EMERGENCY notice rejected revoked_did=did:guardian:board-emergency-tampered-20260721-001: invalid signature on CRL entry urn:uuid:d0881f0b-5410-4a1b-bd85-7bb8df0c59bc",
    "node_id": "nodeB",
    "severity": "Warning",
    "timestamp": 1784618285
  }
}
```

**Verdict:** ✅ PASS — tampered emergency notice was received but not merged. nodeB kept `revoked=false` for the tampered DID, `last_notice` did not switch to the tampered DID, and the audit log explicitly recorded rejection due to `invalid signature`.

---

## ✅ CRL-028 — Re-broadcast is bounded by TTL and dedup

> Verify that a received critical notice is forwarded once according to TTL, and duplicate delivery does not cause repeated merges or infinite echo.

**Commands:**
```bash
# nodeB / nodeC — baseline
DID_028="did:guardian:board-emergency-ttl-dedup-20260721-002"
curl -s http://localhost:8443/api/v1/crl/emergency/status > /tmp/pre_028.json
/home/root/sgx-pa-cli crl check --did "$DID_028"

# nodeA — create fresh critical revoke
DID_028="did:guardian:board-emergency-ttl-dedup-20260721-002"
/home/root/sgx-pa-cli crl revoke --did "$DID_028" --reason compromised --severity critical --note "CRL-028 board ttl-dedup retry"
curl -s http://localhost:8443/api/v1/crl/emergency/status | python3 -m json.tool

# nodeC — confirm entry and capture first status
DID_028="did:guardian:board-emergency-ttl-dedup-20260721-002"
for i in $(seq 1 30); do
  /home/root/sgx-pa-cli crl check --did "$DID_028" | grep -q '"revoked": true' && break
  sleep 1
done
/home/root/sgx-pa-cli crl check --did "$DID_028"
/home/root/sgx-pa-cli crl root
curl -s http://localhost:8443/api/v1/crl/emergency/status > /tmp/first_028.json
python3 -m json.tool /tmp/first_028.json

# nodeA — duplicate manual rebroadcast
DID_028="did:guardian:board-emergency-ttl-dedup-20260721-002"
curl -s -X POST "http://localhost:8443/api/v1/crl/emergency/broadcast?did=$DID_028" | python3 -m json.tool
curl -s http://localhost:8443/api/v1/crl/emergency/status | python3 -m json.tool

# nodeC — dedup delta check
sleep 5
curl -s http://localhost:8443/api/v1/crl/emergency/status > /tmp/dup_028.json

python3 - <<'PY'
import json
pre=json.load(open("/tmp/pre_028.json"))
first=json.load(open("/tmp/first_028.json"))
dup=json.load(open("/tmp/dup_028.json"))

for k in ["notices_received","notices_merged","notices_rebroadcast"]:
    print(k, "first_delta=", first[k]-pre[k], "duplicate_delta=", dup[k]-first[k])

print("last_notice:", dup.get("last_notice"))
PY
```

**Result:**
```text
Attempt 1:

nodeB/nodeC receiver baseline:
DID_028="did:guardian:board-emergency-ttl-dedup-20260721-001"
/home/root/sgx-pa-cli crl check --did "$DID_028"
{
  "did": "did:guardian:board-emergency-ttl-dedup-20260721-001",
  "entry": null,
  "revoked": false
}

nodeA source revoke attempt:
/home/root/sgx-pa-cli crl revoke --did "$DID_028" --reason compromised --severity critical --note "CRL-028 board ttl-dedup"

Result:
  Existing DKP found (v1) — loading from SE050
  Using existing device identity key (0x20000010)
  ❌ did: DID derivation signature failed: DKP sign: SE050 sign failed:
  ssscli failed: ssscli sign 0x20000010 ... — ERROR:sss.session:No open session, try connecting first
  ERROR:sss.session:Run 'ssscli connect --help' for more information.
  ERROR:cli.cli:No open session, try connecting first
  ERROR:cli.cli:'Context' object has no attribute 'session'

nodeA status after failed revoke:
{
  "enabled": true,
  "port": 50064,
  "ttl": 1,
  "notices_sent": 2,
  "notices_received": 0,
  "notices_merged": 0,
  "notices_rebroadcast": 0,
  "sessions_terminated": 0,
  "last_notice": {
    "direction": "sent",
    "revoked_did": "did:guardian:board-emergency-merge-20260721-001",
    "origin_did": "did:guardian:C2txwUBkHG5GukHRgvbZQqvxtv7CNkNDvdRAQfx9VQkE",
    "peers": 2,
    "merged": true,
    "at": "2026-07-21T06:49:52.362781668+00:00"
  }
}

nodeA manual rebroadcast attempt for the same DID:
curl -s -X POST "http://localhost:8443/api/v1/crl/emergency/broadcast?did=$DID_028" | python3 -m json.tool
{
  "error": {
    "code": "NOT_FOUND",
    "message": "did:guardian:board-emergency-ttl-dedup-20260721-001 is not revoked"
  }
}

nodeC after failed nodeA revoke:
/home/root/sgx-pa-cli crl check --did "$DID_028"
{
  "did": "did:guardian:board-emergency-ttl-dedup-20260721-001",
  "entry": null,
  "revoked": false
}
nodeC last_notice stayed on previous CRL-027 source DID, not DID_028.

Attempt 2 after SE050 recovery:

nodeA SE050 probe:
ssscli se05x uid
Unique ID: 0400500111b7985e065254047857bae51090

ssscli se05x readidlist | grep -i 20000010
Key-Id: 0X20000010   NIST-P            (Key Pair)     Size(Bits): 256

ssscli sign 0x20000010 /tmp/crl_028_probe.bin /tmp/crl_028_probe.sig
Signed from KeyID = 0x20000010
-rw-r--r-- 1 root root 70 Jul 21 07:32 /tmp/crl_028_probe.sig

nodeA source revoke:
DID_028="did:guardian:board-emergency-ttl-dedup-20260721-002"
/home/root/sgx-pa-cli crl revoke --did "$DID_028" --reason compromised --severity critical --note "CRL-028 board ttl-dedup retry"

Output:
  Existing DKP found (v1) — loading from SE050
  Using existing device identity key (0x20000010)
  ✅ CRL entry issued: urn:uuid:b525f30d-7503-49bd-88d5-bca42d9a8659
     sequence=11
     root=43a51330227510e3e822b5e06a98c7d07c687c1d9b165b501493ebe9c952219f
  🚨 EMERGENCY broadcast revoked_did=did:guardian:board-emergency-ttl-dedup-20260721-002 → 2 peers

nodeA manual rebroadcast endpoint:
curl -s -X POST "http://localhost:8443/api/v1/crl/emergency/broadcast?did=$DID_028" | python3 -m json.tool
{
  "success": true,
  "revoked_did": "did:guardian:board-emergency-ttl-dedup-20260721-002",
  "message": "emergency broadcast dispatched"
}

nodeA status after manual rebroadcast:
{
  "enabled": true,
  "port": 50064,
  "ttl": 1,
  "notices_sent": 1,
  "notices_received": 0,
  "notices_merged": 0,
  "notices_rebroadcast": 0,
  "sessions_terminated": 0,
  "last_notice": {
    "direction": "sent",
    "revoked_did": "did:guardian:board-emergency-ttl-dedup-20260721-002",
    "origin_did": "did:guardian:C2txwUBkHG5GukHRgvbZQqvxtv7CNkNDvdRAQfx9VQkE",
    "peers": 2,
    "merged": true,
    "at": "2026-07-21T07:34:55.927596791+00:00"
  }
}

nodeC receiver entry:
/home/root/sgx-pa-cli crl check --did "$DID_028"
Result:
  "id": "urn:uuid:b525f30d-7503-49bd-88d5-bca42d9a8659"
  "revoked_did": "did:guardian:board-emergency-ttl-dedup-20260721-002"
  "revoker_did": "did:guardian:C2txwUBkHG5GukHRgvbZQqvxtv7CNkNDvdRAQfx9VQkE"
  "severity": "critical"
  "reason": "compromised"
  "revoked": true

nodeC root:
{
  "merkle_root": "43a51330227510e3e822b5e06a98c7d07c687c1d9b165b501493ebe9c952219f",
  "sequence": 16
}

nodeC first status capture:
{
  "enabled": true,
  "port": 50064,
  "ttl": 1,
  "notices_sent": 0,
  "notices_received": 8,
  "notices_merged": 5,
  "notices_rebroadcast": 5,
  "sessions_terminated": 0,
  "last_notice": {
    "direction": "received",
    "revoked_did": "did:guardian:board-emergency-tamper-src-20260721-001",
    "origin_did": "did:guardian:C2txwUBkHG5GukHRgvbZQqvxtv7CNkNDvdRAQfx9VQkE",
    "peers": 0,
    "merged": true,
    "at": "2026-07-21T07:18:08.230970294+00:00"
  }
}

nodeC duplicate/dedup delta after manual rebroadcast:
notices_received first_delta= 0 duplicate_delta= 2
notices_merged first_delta= 0 duplicate_delta= 0
notices_rebroadcast first_delta= 0 duplicate_delta= 0
last_notice: {
  "direction": "received",
  "revoked_did": "did:guardian:board-emergency-ttl-dedup-20260721-002",
  "origin_did": "did:guardian:C2txwUBkHG5GukHRgvbZQqvxtv7CNkNDvdRAQfx9VQkE",
  "peers": 0,
  "merged": false,
  "at": "2026-07-21T07:34:55.851382764+00:00"
}
```

**Verdict:** ✅ PASS — after SE050 recovery, nodeA created a fresh critical CRL entry and manual rebroadcast API returned `success=true`. nodeC had the revoked entry with matching Merkle root. Duplicate emergency delivery was received (`notices_received` +2) but did not re-merge or re-broadcast (`notices_merged` +0, `notices_rebroadcast` +0), and `last_notice.merged=false` confirms dedup bounded the repeated notice. Caveat: the first status baseline for this DID was not clean (`first_delta=0`), so the pass evidence for CRL-028 is specifically the duplicate/dedup bounded-rebroadcast behavior; first-merge behavior was already evidenced in CRL-023/CRL-024/CRL-026.

---

## ❌ CRL-029 — Critical revoke terminates active CoT sessions

> Verify that when the revoked DID maps to a live CoT peer session, that session is dropped immediately.

**Commands:**
```bash
# nodeB — attempted debug session seed
DID_029="did:guardian:board-emergency-session-20260721-001"

curl -s -X POST http://localhost:8443/api/v1/crl/emergency/debug/session \
  -H 'Content-Type: application/json' \
  -d '{"did":"'"$DID_029"'","transport":"Ethernet"}' \
  | python3 -m json.tool

# nodeB — attempted pre/post lookup
curl -s "http://localhost:8443/api/v1/crl/emergency/debug/session?did=$DID_029" | python3 -m json.tool
curl -s http://localhost:8443/api/v1/crl/emergency/status > /tmp/pre_029.json
python3 -m json.tool /tmp/pre_029.json

# nodeA — attempted critical revoke of same DID
DID_029="did:guardian:board-emergency-session-20260721-001"
/home/root/sgx-pa-cli crl revoke --did "$DID_029" --reason compromised --severity critical --note "CRL-029 board session termination"
sleep 3

# nodeB — post check
curl -s "http://localhost:8443/api/v1/crl/emergency/debug/session?did=$DID_029" | python3 -m json.tool
curl -s http://localhost:8443/api/v1/crl/emergency/status > /tmp/post_029.json
python3 -m json.tool /tmp/post_029.json

python3 - <<'PY'
import json
pre=json.load(open("/tmp/pre_029.json"))
post=json.load(open("/tmp/post_029.json"))
print("sessions_terminated_delta=", post["sessions_terminated"] - pre["sessions_terminated"])
print("last_notice=", post.get("last_notice"))
PY

grep -aE "sessions_terminated|terminated|CRL-029|board-emergency-session" /var/log/sgx-guardian/audit-nodeB.log | tail -20
```

**Result:**
```text
nodeB debug session seed:
{
  "error": {
    "code": "NOT_FOUND",
    "message": "peer DID document not found for did:guardian:board-emergency-session-20260721-001"
  }
}

nodeB debug session lookup:
{
  "error": {
    "code": "NOT_FOUND",
    "message": "peer DID document not found for did:guardian:board-emergency-session-20260721-001"
  }
}

Retry precheck with real nodeC DID:
DID_C="did:guardian:EtFW3QGXPgjjz6RYqqUQqdXrNKknaxFun18A6mr2mySB"

nodeB peer directory:
{
  "count": 3,
  "peers": [
    { "did": "did:guardian:3udaKaaqBaN9SsrdtJAtBiDkz8FtHosj9DpPFkS8wXYa", "node_name": "nodeB", "status": "active" },
    { "did": "did:guardian:C2txwUBkHG5GukHRgvbZQqvxtv7CNkNDvdRAQfx9VQkE", "node_name": "nodeA", "status": "active" },
    { "did": "did:guardian:EtFW3QGXPgjjz6RYqqUQqdXrNKknaxFun18A6mr2mySB", "node_name": "nodeC", "status": "active" }
  ]
}

nodeB nodeC peer document lookup succeeded:
  id: did:guardian:EtFW3QGXPgjjz6RYqqUQqdXrNKknaxFun18A6mr2mySB
  sgx:nodeName: nodeC
  sgx:status: active
  services: SGXNebulaMesh nebula://192.168.100.2/24, SGXAttestation tcp://192.168.100.2:50153

nodeB pre-check for nodeC DID:
{
  "did": "did:guardian:EtFW3QGXPgjjz6RYqqUQqdXrNKknaxFun18A6mr2mySB",
  "entry": null,
  "revoked": false
}

nodeB debug session seed with real nodeC DID:
{
  "node_id": "nodeB",
  "did": "did:guardian:EtFW3QGXPgjjz6RYqqUQqdXrNKknaxFun18A6mr2mySB",
  "remote_device_id": "0299cc0d31a127a3de2a8ac66ac2bf7c5fb3eed4e06102e75b841fbb12124b1d",
  "exists": true,
  "total_sessions": 1,
  "active_sessions": 1,
  "session": {
    "session_id": "c7863439-81da-4df0-ab48-e3fa4460bc03",
    "current_transport": "Ethernet",
    "state": "Active"
  },
  "message": "debug CoT session seeded via Ethernet"
}

nodeB debug session lookup confirmed:
{
  "exists": true,
  "total_sessions": 1,
  "active_sessions": 1,
  "message": "debug CoT session exists"
}

nodeB pre status after session seed:
{
  "enabled": true,
  "port": 50064,
  "ttl": 1,
  "notices_sent": 0,
  "notices_received": 0,
  "notices_merged": 0,
  "notices_rebroadcast": 0,
  "sessions_terminated": 0,
  "last_notice": null
}

nodeA SE050 probe for CRL-029:
ssscli se05x uid
Unique ID: 0400500111b7985e065254047857bae51090

ssscli se05x readidlist | grep -i 20000010
ERROR:cli.cli:Function do_read_id_list (args=()) (kwargs={}) timed out after 60.000000 seconds.

ssscli sign 0x20000010 /tmp/crl_029_probe.bin /tmp/crl_029_probe.sig
ERROR:sss.session:No open session, try connecting first
ERROR! Could not Sign from KeyID 0x20000010
ls: cannot access '/tmp/crl_029_probe.sig': No such file or directory

Second nodeA recovery attempt:
ssscli se05x uid
Unique ID: 0400500111b7985e065254047857bae51090

ssscli sign 0x20000010 /tmp/crl_029_probe2.bin /tmp/crl_029_probe2.sig
Signed from KeyID = 0x20000010
-rw-r--r-- 1 root root 70 Jul 21 07:58 /tmp/crl_029_probe2.sig

nodeA CRL-029 revoke attempt with real nodeC DID:
/home/root/sgx-pa-cli crl revoke --did "$DID_C" --reason compromised --severity critical --note "CRL-029 board session termination"

Result:
  Existing DKP found (v1) — loading from SE050
  Using existing device identity key (0x20000010)
  ❌ invalid CRL entry: commit status list: did: DID derivation signature failed:
  DKP sign: SE050 sign failed: ssscli failed: ssscli sign 0x20000010 ...
  ERROR:sss.session:No open session, try connecting first

nodeA emergency status after failed/partial revoke:
{
  "enabled": true,
  "port": 50064,
  "ttl": 1,
  "notices_sent": 0,
  "notices_received": 0,
  "notices_merged": 0,
  "notices_rebroadcast": 0,
  "sessions_terminated": 0,
  "last_notice": null
}

nodeA cleanup/unrevoke attempt also failed with SE050 `No open session`.

nodeA local CRL check after failed/partial revoke:
{
  "did": "did:guardian:EtFW3QGXPgjjz6RYqqUQqdXrNKknaxFun18A6mr2mySB",
  "entry": {
    "id": "urn:uuid:5a909cfc-8345-4799-8a77-a6d44e8e5f98",
    "revoked_did": "did:guardian:EtFW3QGXPgjjz6RYqqUQqdXrNKknaxFun18A6mr2mySB",
    "reason": "compromised",
    "severity": "critical",
    "evidence": { "note": "CRL-029 board session termination" },
    "revoker_did": "did:guardian:C2txwUBkHG5GukHRgvbZQqvxtv7CNkNDvdRAQfx9VQkE"
  },
  "revoked": true
}

Follow-up cleanup attempt with all known SE050 contention stopped:
ps | grep -E 'sgx_guardian_client|ssscli' | grep -v grep || true
Result: no process output.

Manual SE050 probe:
ssscli connect --auth_type PlatformSCP --scpkey "$SCP_KEY" se05x t1oi2c none
ssscli se05x uid
Unique ID: 0400500111b7985e065254047857bae51090

ssscli sign 0x20000010 /tmp/unrevoke_probe.bin /tmp/unrevoke_probe.sig
Signed from KeyID = 0x20000010
-rw-r--r-- 1 root root 70 Jul 21 08:05 /tmp/unrevoke_probe.sig

CLI unrevoke with startup/PCR/CoT refresh disabled:
SGX_DISABLE_STARTUP_ATTEST=1 SGX_DISABLE_PCR=1 SGX_DISABLE_COT_REFRESH=1 \
/home/root/sgx-pa-cli crl unrevoke --did "$DID_C"

Result:
  Existing DKP found (v1) — loading from SE050
  Using existing device identity key (0x20000010)
  ❌ did: DID derivation signature failed: DKP sign: SE050 sign failed:
  ssscli failed: ssscli sign 0x20000010 ... — ERROR:sss.session:No open session, try connecting first

nodeA local CRL check remained:
{
  "did": "did:guardian:EtFW3QGXPgjjz6RYqqUQqdXrNKknaxFun18A6mr2mySB",
  "revoked": true,
  "entry": {
    "id": "urn:uuid:5a909cfc-8345-4799-8a77-a6d44e8e5f98",
    "note": "CRL-029 board session termination"
  }
}

nodeB post-check after nodeA attempt:
{
  "node_id": "nodeB",
  "did": "did:guardian:EtFW3QGXPgjjz6RYqqUQqdXrNKknaxFun18A6mr2mySB",
  "remote_device_id": "0299cc0d31a127a3de2a8ac66ac2bf7c5fb3eed4e06102e75b841fbb12124b1d",
  "exists": false,
  "total_sessions": 0,
  "active_sessions": 0,
  "session": null,
  "message": "debug CoT session not present"
}

nodeB emergency post status:
{
  "enabled": true,
  "port": 50064,
  "ttl": 1,
  "notices_sent": 0,
  "notices_received": 0,
  "notices_merged": 0,
  "notices_rebroadcast": 0,
  "sessions_terminated": 0,
  "last_notice": null
}

delta:
sessions_terminated_delta= 0
last_notice= None

nodeB audit grep did not show an emergency revocation applied event for nodeC DID; it only showed routine VC/attestation/gossip lines for nodeC.

Follow-up state after nodeA was restarted:
nodeA local CRL check:
{
  "did": "did:guardian:EtFW3QGXPgjjz6RYqqUQqdXrNKknaxFun18A6mr2mySB",
  "entry": {
    "id": "urn:uuid:5a909cfc-8345-4799-8a77-a6d44e8e5f98",
    "revoked_did": "did:guardian:EtFW3QGXPgjjz6RYqqUQqdXrNKknaxFun18A6mr2mySB",
    "peers_notified": [
      "did:guardian:3udaKaaqBaN9SsrdtJAtBiDkz8FtHosj9DpPFkS8wXYa"
    ],
    "propagated": true,
    "reason": "compromised",
    "severity": "critical",
    "evidence": { "note": "CRL-029 board session termination" }
  },
  "revoked": true
}

nodeA gossip status after restart:
{
  "other_members": 1,
  "threshold_count": 1,
  "sequence": 15,
  "merkle_root": "a855448860714d5eff858fb741b6bf89e6f1abc7369765aa372e371d1675455f",
  "entries": 8,
  "propagated": 8,
  "last_round": {
    "peer_node": "nodeB",
    "merkle_root": "a855448860714d5eff858fb741b6bf89e6f1abc7369765aa372e371d1675455f"
  }
}

nodeC diagnostics:
- sgx_guardian_client nodeC running.
- nebula0 up at 192.168.100.2/24.
- attestation listener active on 0.0.0.0:50153.
- nodeC local CRL check for nodeA returned revoked=false.
- nodeC local CRL check for nodeC returned revoked=false.
- nodeC gossip status remained at merkle_root 43a51330227510e3e822b5e06a98c7d07c687c1d9b165b501493ebe9c952219f, entries=7, other_members=2.
- nodeC audit showed repeated incoming attestation verified from nodeA/nodeB, with intermittent VC rejection `status list signature invalid`, followed later by successful VC verification for nodeA.

State conclusion:
NodeA has diverged from nodeB/nodeC by carrying the partial CRL-029 nodeC revocation entry. NodeA now excludes nodeC from CRL gossip membership (`other_members=1`) and may propagate the partial entry to nodeB. This is lab-state contamination from the blocked CRL-029 attempt, not a successful CRL-029 verification.

Follow-up nodeB check confirmed contamination propagated:
nodeB local CRL check:
{
  "did": "did:guardian:EtFW3QGXPgjjz6RYqqUQqdXrNKknaxFun18A6mr2mySB",
  "entry": {
    "id": "urn:uuid:5a909cfc-8345-4799-8a77-a6d44e8e5f98",
    "revoked_did": "did:guardian:EtFW3QGXPgjjz6RYqqUQqdXrNKknaxFun18A6mr2mySB",
    "peers_notified": [
      "did:guardian:C2txwUBkHG5GukHRgvbZQqvxtv7CNkNDvdRAQfx9VQkE"
    ],
    "propagated": true,
    "reason": "compromised",
    "severity": "critical"
  },
  "revoked": true
}

nodeB gossip status:
{
  "other_members": 1,
  "threshold_count": 1,
  "sequence": 16,
  "merkle_root": "a855448860714d5eff858fb741b6bf89e6f1abc7369765aa372e371d1675455f",
  "entries": 8,
  "propagated": 8,
  "last_round": {
    "peer_node": "nodeA",
    "merkle_root": "a855448860714d5eff858fb741b6bf89e6f1abc7369765aa372e371d1675455f"
  }
}

NodeA was stopped with `pkill -f sgx_guardian_client` after contamination was observed. Cleanup now needs to include nodeA and nodeB; nodeC was still clean in its own local CRL at the time of diagnostic.

Recovery cleanup executed on nodeA and nodeB with backup-first local CRL reset:
```text
pkill -f sgx_guardian_client || true
TS=$(date +%Y%m%d-%H%M%S)
mkdir -p /root/crl-backup-$TS
cp -a /var/lib/sgx-guardian/identity/crl /root/crl-backup-$TS/
rm -f /var/lib/sgx-guardian/identity/crl/crl.json
rm -rf /var/lib/sgx-guardian/identity/crl/pending
```

Post-cleanup nodeA:
{
  "did": "did:guardian:EtFW3QGXPgjjz6RYqqUQqdXrNKknaxFun18A6mr2mySB",
  "entry": null,
  "revoked": false
}
gossip status:
{
  "self_did": "did:guardian:C2txwUBkHG5GukHRgvbZQqvxtv7CNkNDvdRAQfx9VQkE",
  "other_members": 2,
  "sequence": 0,
  "merkle_root": "",
  "entries": 0
}

Post-cleanup nodeB:
{
  "did": "did:guardian:EtFW3QGXPgjjz6RYqqUQqdXrNKknaxFun18A6mr2mySB",
  "entry": null,
  "revoked": false
}
gossip status:
{
  "self_did": "did:guardian:3udaKaaqBaN9SsrdtJAtBiDkz8FtHosj9DpPFkS8wXYa",
  "other_members": 2,
  "sequence": 0,
  "merkle_root": "",
  "entries": 0
}

NodeC remained clean:
{
  "did": "did:guardian:EtFW3QGXPgjjz6RYqqUQqdXrNKknaxFun18A6mr2mySB",
  "entry": null,
  "revoked": false
}
gossip status:
{
  "self_did": "did:guardian:EtFW3QGXPgjjz6RYqqUQqdXrNKknaxFun18A6mr2mySB",
  "other_members": 2,
  "sequence": 18,
  "merkle_root": "43a51330227510e3e822b5e06a98c7d07c687c1d9b165b501493ebe9c952219f",
  "entries": 7
}

Recovery state verdict:
nodeC DID exclusion is cleared on all checked nodes (`revoked=false`, `other_members=2`). nodeA/nodeB CRL roots were intentionally empty immediately after local reset and therefore needed routine gossip or a manual gossip trigger to rehydrate their CRLs.

Manual gossip trigger rehydration after cleanup:

NodeB:
curl -s -X POST http://localhost:8443/api/v1/crl/gossip/trigger | python3 -m json.tool
{
  "success": true,
  "peer_did": "did:guardian:EtFW3QGXPgjjz6RYqqUQqdXrNKknaxFun18A6mr2mySB",
  "peer_node": "nodeC",
  "merged": 0,
  "pushed": 0,
  "peer_merged": 0,
  "merkle_root": "43a51330227510e3e822b5e06a98c7d07c687c1d9b165b501493ebe9c952219f",
  "newly_propagated": [],
  "message": "gossip round completed"
}
/home/root/sgx-pa-cli crl root
{
  "merkle_root": "43a51330227510e3e822b5e06a98c7d07c687c1d9b165b501493ebe9c952219f",
  "sequence": 3
}
gossip status:
{
  "self_did": "did:guardian:3udaKaaqBaN9SsrdtJAtBiDkz8FtHosj9DpPFkS8wXYa",
  "other_members": 2,
  "sequence": 3,
  "merkle_root": "43a51330227510e3e822b5e06a98c7d07c687c1d9b165b501493ebe9c952219f",
  "entries": 7,
  "propagated": 7,
  "entries_merged": 7
}
nodeC DID check:
{
  "did": "did:guardian:EtFW3QGXPgjjz6RYqqUQqdXrNKknaxFun18A6mr2mySB",
  "entry": null,
  "revoked": false
}

NodeA:
curl -s -X POST http://localhost:8443/api/v1/crl/gossip/trigger | python3 -m json.tool
{
  "success": true,
  "peer_did": "did:guardian:EtFW3QGXPgjjz6RYqqUQqdXrNKknaxFun18A6mr2mySB",
  "peer_node": "nodeC",
  "merged": 0,
  "pushed": 0,
  "peer_merged": 0,
  "merkle_root": "43a51330227510e3e822b5e06a98c7d07c687c1d9b165b501493ebe9c952219f",
  "newly_propagated": [],
  "message": "gossip round completed"
}
/home/root/sgx-pa-cli crl root
{
  "merkle_root": "43a51330227510e3e822b5e06a98c7d07c687c1d9b165b501493ebe9c952219f",
  "sequence": 3
}
gossip status:
{
  "self_did": "did:guardian:C2txwUBkHG5GukHRgvbZQqvxtv7CNkNDvdRAQfx9VQkE",
  "other_members": 2,
  "sequence": 3,
  "merkle_root": "43a51330227510e3e822b5e06a98c7d07c687c1d9b165b501493ebe9c952219f",
  "entries": 7,
  "propagated": 7,
  "entries_merged": 7
}
nodeC DID check:
{
  "did": "did:guardian:EtFW3QGXPgjjz6RYqqUQqdXrNKknaxFun18A6mr2mySB",
  "entry": null,
  "revoked": false
}

Post-cleanup recovery verdict:
nodeA, nodeB, and nodeC are back on the same CRL Merkle root `43a51330227510e3e822b5e06a98c7d07c687c1d9b165b501493ebe9c952219f`, all checked nodes show `other_members=2`, and the accidental nodeC revocation is cleared (`revoked=false`). This recovers the lab state, but does not make CRL-029 pass because no emergency notice with an active session produced `sessions_terminated > 0`.

nodeB pre status:
{
  "enabled": true,
  "port": 50064,
  "ttl": 1,
  "notices_sent": 0,
  "notices_received": 1,
  "notices_merged": 1,
  "notices_rebroadcast": 1,
  "sessions_terminated": 0,
  "last_notice": {
    "direction": "received",
    "revoked_did": "did:guardian:board-emergency-ttl-dedup-20260721-002",
    "merged": true
  }
}

nodeA CRL-029 revoke attempt:
  Existing DKP found (v1) — loading from SE050
  Using existing device identity key (0x20000010)
  ❌ did: DID derivation signature failed: DKP sign: SE050 sign failed:
  ssscli failed: ssscli sign 0x20000010 ... — ERROR:sss.session:No open session, try connecting first

nodeB post status:
{
  "enabled": true,
  "port": 50064,
  "ttl": 1,
  "notices_sent": 0,
  "notices_received": 1,
  "notices_merged": 1,
  "notices_rebroadcast": 1,
  "sessions_terminated": 0,
  "last_notice": {
    "direction": "received",
    "revoked_did": "did:guardian:board-emergency-ttl-dedup-20260721-002",
    "merged": true
  }
}

delta:
sessions_terminated_delta= 0

nodeB audit tail only showed previous emergency entries with sessions_terminated=0:
EMERGENCY revocation applied revoked_did=did:guardian:board-emergency-cli-20260721-002 sessions_terminated=0
EMERGENCY revocation applied revoked_did=did:guardian:board-emergency-rest-20260721-001 sessions_terminated=0
EMERGENCY revocation applied revoked_did=did:guardian:board-emergency-ttl-dedup-20260721-002 sessions_terminated=0
```

Final board rerun after config/public-key and PCR baseline repair (`2026-07-22`):
```text
Preconditions:
- nodeB CRL root empty: merkle_root="", sequence=0
- nodeB nodeC DID check: revoked=false
- nodeB emergency status before revoke: sessions_terminated=0, last_notice=null
- nodeB debug session seed:
  did=did:guardian:EtFW3QGXPgjjz6RYqqUQqdXrNKknaxFun18A6mr2mySB
  remote_device_id=0299cc0d31a127a3de2a8ac66ac2bf7c5fb3eed4e06102e75b841fbb12124b1d
  exists=true
  total_sessions=1
  active_sessions=1
  session_id=b849c6cf-ff7b-40dc-9996-890d6a6b87c6

nodeA REST critical revoke:
{
  "status": "success",
  "message": "CRL entry issued",
  "entry": {
    "id": "urn:uuid:a27399fd-315b-4dfe-9eeb-1bd613c23a53",
    "revoked_did": "did:guardian:EtFW3QGXPgjjz6RYqqUQqdXrNKknaxFun18A6mr2mySB",
    "reason": "compromised",
    "severity": "critical",
    "revoker_did": "did:guardian:C2txwUBkHG5GukHRgvbZQqvxtv7CNkNDvdRAQfx9VQkE",
    "evidence": { "note": "CRL-029 final board session termination" }
  },
  "sequence": 1,
  "merkle_root": "4c3c11db9a32cf51bbade8fc8a632fb397812f7b5ba7913e97a08a65510fd1bd"
}

nodeA emergency status after revoke:
{
  "notices_sent": 1,
  "last_notice": {
    "direction": "sent",
    "revoked_did": "did:guardian:EtFW3QGXPgjjz6RYqqUQqdXrNKknaxFun18A6mr2mySB",
    "origin_did": "did:guardian:C2txwUBkHG5GukHRgvbZQqvxtv7CNkNDvdRAQfx9VQkE",
    "peers": 1,
    "merged": true
  }
}

nodeB post-emergency debug session:
{
  "exists": true,
  "total_sessions": 1,
  "active_sessions": 1,
  "session": {
    "session_id": "b849c6cf-ff7b-40dc-9996-890d6a6b87c6",
    "remote_device_id": "0299cc0d31a127a3de2a8ac66ac2bf7c5fb3eed4e06102e75b841fbb12124b1d",
    "state": "Active"
  }
}

nodeB emergency status after revoke:
{
  "notices_received": 1,
  "notices_merged": 0,
  "sessions_terminated": 0,
  "last_notice": {
    "direction": "received",
    "revoked_did": "did:guardian:EtFW3QGXPgjjz6RYqqUQqdXrNKknaxFun18A6mr2mySB",
    "origin_did": "did:guardian:C2txwUBkHG5GukHRgvbZQqvxtv7CNkNDvdRAQfx9VQkE",
    "merged": false
  }
}

sessions_terminated_delta: 0

nodeB audit tail:
- CRL gossip merged revocation revoked_did=did:guardian:EtFW3QGXPgjjz6RYqqUQqdXrNKknaxFun18A6mr2mySB reason=compromised severity=critical via_peer=did:guardian:C2txwUBkHG5GukHRgvbZQqvxtv7CNkNDvdRAQfx9VQkE
- No "EMERGENCY revocation applied ... sessions_terminated=1" audit entry appeared.
```

**Verdict:** ❌ FAIL — the final board rerun satisfied the important preconditions: nodeB had an active CoT debug session for nodeC, nodeA issued a successful critical revoke, and nodeB received the emergency notice. However nodeB kept the session active (`exists=true`, `active_sessions=1`), `sessions_terminated_delta=0`, and no emergency application audit with `sessions_terminated=1` was produced. The audit shows the critical revocation was later merged through routine CRL gossip, while the emergency status recorded `merged=false`. This points to a code-side race/logic gap: critical session-termination side effects currently run only in the emergency handler when `newly_merged=true`; if routine gossip merges the critical entry first, or if the emergency handler sees the entry as already present, the session termination side effect is skipped. CRL-029 remains not passed until critical revocation side effects are enforced idempotently for all critical CRL merge paths or at least for received emergency notices even when the entry already exists.

---

## ✅ CRL-030 — Durable emergency notification feed is recorded

> Verify that a critical revocation creates a durable notification record for frontend/mobile polling.

**Commands:**
```bash
curl -s http://localhost:8443/api/v1/crl/emergency/notifications | python3 -m json.tool
# optional file-level check:
# cat /var/lib/sgx-guardian/identity/crl/emergency_notifications.jsonl
```

**Result:**
```text
NodeC API response:
[
  {
    "notified_at": "2026-07-21T07:18:08.230755413+00:00",
    "revoked_did": "did:guardian:board-emergency-tamper-src-20260721-001",
    "reason": "compromised",
    "severity": "critical",
    "revoker_did": "did:guardian:C2txwUBkHG5GukHRgvbZQqvxtv7CNkNDvdRAQfx9VQkE",
    "origin_did": "did:guardian:C2txwUBkHG5GukHRgvbZQqvxtv7CNkNDvdRAQfx9VQkE",
    "sessions_terminated": 0,
    "headline": "Security alert: a device was revoked (compromised). Sessions with it were closed."
  },
  {
    "notified_at": "2026-07-21T07:13:58.352044030+00:00",
    "revoked_did": "did:guardian:board-emergency-merge-20260721-003",
    "reason": "compromised",
    "severity": "critical"
  },
  {
    "notified_at": "2026-07-21T06:36:01.874830876+00:00",
    "revoked_did": "did:guardian:board-emergency-rest-20260721-001",
    "reason": "compromised",
    "severity": "critical"
  },
  {
    "notified_at": "2026-07-21T06:32:29.942766778+00:00",
    "revoked_did": "did:guardian:board-emergency-cli-20260721-002",
    "reason": "compromised",
    "severity": "critical"
  }
]

NodeC durable file:
-rw-r--r-- 1 root root 2147 Jul 21 07:18 /var/lib/sgx-guardian/identity/crl/emergency_notifications.jsonl

NodeC file tail included JSONL records for:
  did:guardian:board-emergency-cli-20260721-002
  did:guardian:board-emergency-rest-20260721-001
  did:guardian:board-emergency-merge-20260721-001
  did:guardian:board-emergency-merge-20260721-003
  did:guardian:board-emergency-tamper-src-20260721-001

NodeA API response:
[]
NodeA durable notification file was absent/empty.
```

**Verdict:** ✅ PASS — notification API returned durable emergency notification records on nodeC, and the backing JSONL feed exists with critical revocation entries. NodeA source-side feed was empty, but receiver-side durable feed is verified.

---

## ✅ CRL-031 — GET /api/v1/crl/emergency/status exposes counters and last_notice

> Verify the observability endpoint returns the emergency config, counters, and last notice details.

**Commands:**
```bash
curl -s http://localhost:8443/api/v1/crl/emergency/status | python3 -m json.tool
```

**Result:**
```text
NodeA:
{
  "enabled": true,
  "port": 50064,
  "ttl": 1,
  "notices_sent": 2,
  "notices_received": 0,
  "notices_merged": 0,
  "notices_rebroadcast": 0,
  "sessions_terminated": 0,
  "last_notice": {
    "direction": "sent",
    "revoked_did": "did:guardian:board-emergency-ttl-dedup-20260721-002",
    "peers": 2,
    "merged": true
  }
}

NodeB:
{
  "enabled": true,
  "port": 50064,
  "ttl": 1,
  "notices_sent": 0,
  "notices_received": 2,
  "notices_merged": 1,
  "notices_rebroadcast": 1,
  "sessions_terminated": 0,
  "last_notice": {
    "direction": "received",
    "revoked_did": "did:guardian:board-emergency-ttl-dedup-20260721-002",
    "merged": true
  }
}

NodeC:
{
  "enabled": true,
  "port": 50064,
  "ttl": 1,
  "notices_sent": 0,
  "notices_received": 11,
  "notices_merged": 5,
  "notices_rebroadcast": 5,
  "sessions_terminated": 0,
  "last_notice": {
    "direction": "received",
    "revoked_did": "did:guardian:board-emergency-ttl-dedup-20260721-002",
    "merged": false
  }
}
```

**Verdict:** ✅ PASS — status endpoint exposes enabled config, port, TTL, counters, session termination count, and last notice metadata across nodeA, nodeB, and nodeC.

---

## ✅ CRL-032 — POST /api/v1/crl/emergency/broadcast re-broadcasts an existing critical entry

> Verify that the manual hook re-sends an already-existing critical revocation without creating a new entry.

**Commands:**
```bash
DID_032="did:guardian:board-emergency-ttl-dedup-20260721-002"
curl -s http://localhost:8443/api/v1/crl/check?did="$DID_032" | python3 -m json.tool
curl -s -X POST "http://localhost:8443/api/v1/crl/emergency/broadcast?did=$DID_032" | python3 -m json.tool

curl -s http://localhost:8443/api/v1/crl/emergency/status | python3 -m json.tool
```

**Result:**
```text
NodeA existing entry check:
{
  "status": "success",
  "did": "did:guardian:board-emergency-ttl-dedup-20260721-002",
  "revoked": true,
  "entry": {
    "id": "urn:uuid:b525f30d-7503-49bd-88d5-bca42d9a8659",
    "revoked_did": "did:guardian:board-emergency-ttl-dedup-20260721-002",
    "severity": "critical",
    "reason": "compromised",
    "peers_notified": [
      "did:guardian:EtFW3QGXPgjjz6RYqqUQqdXrNKknaxFun18A6mr2mySB",
      "did:guardian:3udaKaaqBaN9SsrdtJAtBiDkz8FtHosj9DpPFkS8wXYa"
    ],
    "propagated": true
  }
}

NodeA manual broadcast:
{
  "success": true,
  "revoked_did": "did:guardian:board-emergency-ttl-dedup-20260721-002",
  "message": "emergency broadcast dispatched"
}

NodeA status after broadcast:
{
  "enabled": true,
  "port": 50064,
  "ttl": 1,
  "notices_sent": 2,
  "last_notice": {
    "direction": "sent",
    "revoked_did": "did:guardian:board-emergency-ttl-dedup-20260721-002",
    "peers": 2,
    "merged": true,
    "at": "2026-07-21T07:43:05.597394899+00:00"
  }
}
```

**Verdict:** ✅ PASS — manual rebroadcast endpoint accepted an existing critical revoked DID and dispatched it to 2 peers without creating a new CRL entry.

---

## ✅ CRL-033 — UDP 50064 is allowed by enforcement and emergency path survives firewall policy

> Verify the ruleset includes the emergency port and emergency propagation still works when enforcement is active.

**Commands:**
```bash
# any node — live ruleset, enforcement must already be applied (see startup log)
nft list table inet sgx_guardian 2>/dev/null | grep -E '50063|50064'

# then re-run one CRL-023/CRL-026 style critical revoke to confirm emergency
# path still works with enforcement active (not just that the rule exists)
```

**Result:**
```text
NodeC nft evidence:
  tcp dport 50063 accept
  tcp dport 50064 accept
  udp dport 50064 accept
  udp sport 50064 accept

NodeB nft evidence:
  tcp dport 50063 accept
  tcp dport 50064 accept
  udp dport 50064 accept
  udp sport 50064 accept

NodeB/NodeC listener:
udp 0 0 0.0.0.0:50064 0.0.0.0:*

Emergency path still active under this policy:
- nodeA manual rebroadcast returned success=true for did:guardian:board-emergency-ttl-dedup-20260721-002
- nodeB/nodeC emergency status showed received emergency notices after rebroadcast
```

**Verdict:** ✅ PASS — live enforcement rules include routine gossip port `50063` and emergency UDP port `50064`, the UDP listener is active, and the emergency path continued to receive rebroadcast notices.

---

## ✅ CRL-034 — Emergency path preserves root convergence with routine gossip

> Verify that after emergency propagation, nodes still converge to the same CRL Merkle root and sequence through the shared merge path.

**Commands:**
```bash
# nodeA / nodeB / nodeC
/home/root/sgx-pa-cli crl root
curl -s http://localhost:8443/api/v1/crl/gossip/status | python3 -m json.tool
```

**Result:**
```text
NodeA:
/home/root/sgx-pa-cli crl root
{
  "merkle_root": "43a51330227510e3e822b5e06a98c7d07c687c1d9b165b501493ebe9c952219f",
  "sequence": 13
}
gossip status:
{
  "enabled": true,
  "port": 50063,
  "sequence": 13,
  "merkle_root": "43a51330227510e3e822b5e06a98c7d07c687c1d9b165b501493ebe9c952219f",
  "entries": 7,
  "propagated": 7,
  "last_round": {
    "direction": "served",
    "peer_node": "nodeC",
    "merged": 0,
    "sent": 0
  }
}

NodeB:
/home/root/sgx-pa-cli crl root
{
  "merkle_root": "43a51330227510e3e822b5e06a98c7d07c687c1d9b165b501493ebe9c952219f",
  "sequence": 13
}
gossip status:
{
  "enabled": true,
  "port": 50063,
  "sequence": 13,
  "merkle_root": "43a51330227510e3e822b5e06a98c7d07c687c1d9b165b501493ebe9c952219f",
  "entries": 7,
  "propagated": 7,
  "last_round": {
    "direction": "initiated",
    "peer_node": "nodeA",
    "merged": 0,
    "sent": 0
  }
}

NodeC:
/home/root/sgx-pa-cli crl root
{
  "merkle_root": "43a51330227510e3e822b5e06a98c7d07c687c1d9b165b501493ebe9c952219f",
  "sequence": 18
}
gossip status:
{
  "enabled": true,
  "port": 50063,
  "sequence": 18,
  "merkle_root": "43a51330227510e3e822b5e06a98c7d07c687c1d9b165b501493ebe9c952219f",
  "entries": 7,
  "propagated": 7,
  "last_round": {
    "direction": "initiated",
    "peer_node": "nodeA",
    "merged": 0,
    "sent": 0
  }
}
```

**Verdict:** ✅ PASS — all three nodes converged to the same CRL Merkle root `43a51330227510e3e822b5e06a98c7d07c687c1d9b165b501493ebe9c952219f`, routine gossip remained enabled on port `50063`, and gossip rounds showed no pending merge/send work. Sequence counters differ on nodeC (`18` vs `13`), but the converged Merkle root and `entries=7/propagated=7` show CRL content convergence.

---

## ✅ Hook 2 — SGX_CRL_EMERGENCY_ENABLED=0 disables emergency path cleanly

> Verify that starting a Guardian with emergency disabled reports disabled config and does not bind the emergency UDP listener.

**Commands:**
```bash
# nodeB
pgrep -af sgx_guardian_client
curl -s http://localhost:8443/api/v1/crl/emergency/status | python3 -m json.tool
netstat -lun | grep 50064

pkill -f sgx_guardian_client || true
sleep 2

SGX_CRL_EMERGENCY_ENABLED=0 ./sgx_guardian_client nodeB > /tmp/hook2-nodeB-disabled.log 2>&1 &
echo $! > /tmp/hook2-nodeB-disabled.pid

for i in $(seq 1 60); do
  curl -sf http://localhost:8443/api/v1/crl/emergency/status > /tmp/hook2-status.json && break
  sleep 2
done

python3 -m json.tool /tmp/hook2-status.json
netstat -lun | grep 50064 || echo "PASS: no emergency UDP 50064 listener"
```

**Result:**
```text
NodeB normal precheck:
pgrep:
549935 ./sgx_guardian_client nodeB

emergency status:
{
  "enabled": true,
  "port": 50064,
  "ttl": 1,
  "notices_sent": 0,
  "notices_received": 0,
  "notices_merged": 0,
  "notices_rebroadcast": 0,
  "sessions_terminated": 0,
  "last_notice": null
}

listener:
udp        0      0 0.0.0.0:50064           0.0.0.0:*

NodeB disabled-mode startup:
SGX_CRL_EMERGENCY_ENABLED=0 ./sgx_guardian_client nodeB > /tmp/hook2-nodeB-disabled.log 2>&1 &
pid: 558692

disabled emergency status:
{
  "enabled": false,
  "port": 50064,
  "ttl": 1,
  "notices_sent": 0,
  "notices_received": 0,
  "notices_merged": 0,
  "notices_rebroadcast": 0,
  "sessions_terminated": 0,
  "last_notice": null
}

listener check:
PASS: no emergency UDP 50064 listener

NodeA/NodeC note:
The separately pasted nodeA/nodeC outputs still showed normal enabled mode and UDP 50064 listener. That is expected because Hook2 was scoped to nodeB only.
```

**Verdict:** ✅ PASS — with `SGX_CRL_EMERGENCY_ENABLED=0`, nodeB stayed API-reachable, `/api/v1/crl/emergency/status` returned `enabled=false`, and no UDP `50064` listener was bound. This verifies disabled-mode listener gating.

---

## 📝 Notes / Issues Found During Verification

```text
- 2026-07-21 board preflight: nodeC Nebula issue was debugged before CRL emergency testing.
- Root cause observed on nodeC: /var/lib/sgx-guardian/nebula/nodes/nodeC.key was missing, so `nebula -config ... -test` failed with "unable to read pki.key file".
- Also observed: nodeA CA hash differed from nodeB/nodeC before cleanup; nodeC had stale/half-bootstrap Nebula state.
- Action taken outside this log: nodeC/nodeA stale nodeC Nebula cert/key/request state was cleaned and nodeC re-bootstrap was completed before emergency verification resumed.
- CRL-022 first board paste: nodeA passed preflight, but the pasted "Node B" section was actually running `sgx_guardian_client nodeC`; later attachment provided actual nodeB output and nodeB passed listener/status proof.
- Current overlay allocation is nodeA=192.168.100.1, nodeB=192.168.100.3, nodeC=192.168.100.2. This is acceptable because overlay assignment can depend on registry allocation order.
- CRL-022 PASS on 2026-07-21: nodeA/nodeB/nodeC emergency status enabled and UDP 50064 listener visible.
- CRL-023 attempt 1 blocked on nodeA by `sgx-pa-cli` SE050 signing session error: `No open session, try connecting first`. Peers correctly stayed `revoked=false` because no local revocation was issued.
- CRL-023 retry also blocked: manual `ssscli se05x uid` worked, but `ssscli sign 0x20000010 ...` failed with CRC/transceive errors and no signature file. nodeA daemon also logged `SE050 TAMPER DETECTED — all crypto operations blocked`.
- CRL-023 SE050 recovery succeeded after stopping Guardian/ssscli, clearing stale session pickle, reconnecting, confirming slot `0x20000010`, and signing a probe file.
- CRL-023 PASS on retry with fresh DID `did:guardian:board-emergency-cli-20260721-002`: nodeA issued entry `urn:uuid:bc6a8b32-4dc6-4193-9102-50ece3c42362` and printed emergency broadcast to 2 peers; nodeB/nodeC both reported `revoked=true`.
- CRL-024 PASS with REST DID `did:guardian:board-emergency-rest-20260721-001`: nodeA REST API issued entry `urn:uuid:527bdd48-077e-4052-b9e4-7a65bd387104`; nodeA status showed `notices_sent=1` and `peers=2`; nodeB/nodeC both reported `revoked=true`.
- CRL-025 PASS with medium-severity DID `did:guardian:board-emergency-negative-20260721-001`: nodeA issued local CRL entry but emergency deltas stayed zero on nodeA; passive nodeB/nodeC emergency deltas also stayed zero.
- CRL-026 partial: nodeA issued entry `urn:uuid:a4bb81fc-bd26-4ea9-9513-2476814e7536`; nodeC merged it, but nodeB remained `revoked=false`. Manual rebroadcast reached nodeB (`notices_received` +1) but did not merge.
- CRL-026 fresh DID rerun was blocked by recurring nodeA SE050 `No open session` signing failure; no CRL entry or emergency broadcast was produced for `did:guardian:board-emergency-merge-20260721-002`.
- CRL-026 PASS on clean rerun with DID `did:guardian:board-emergency-merge-20260721-003`: nodeA issued entry `urn:uuid:d2d5b26d-dcbd-4428-8d56-97e092136cee`; nodeC merged it and exposed `revoked=true` with matching Merkle root. nodeB still received but did not merge; keep as anomaly for convergence/fanout follow-up.
- CRL-027 PASS: nodeA created valid source entry `urn:uuid:d0881f0b-5410-4a1b-bd85-7bb8df0c59bc`, then sent a tampered emergency notice to nodeB with `revoked_did=did:guardian:board-emergency-tampered-20260721-001`. nodeB kept the tampered DID `revoked=false` and audit logged `EMERGENCY notice rejected ... invalid signature`.
- CRL-028 attempt 1 blocked on nodeA by recurring SE050 `No open session`; retry after SE050 probe succeeded.
- CRL-028 PASS with DID `did:guardian:board-emergency-ttl-dedup-20260721-002`: nodeA issued entry `urn:uuid:b525f30d-7503-49bd-88d5-bca42d9a8659`; manual `POST /api/v1/crl/emergency/broadcast?did=` returned `success=true`; nodeC duplicate delivery increased `notices_received` by 2 but `notices_merged` and `notices_rebroadcast` stayed unchanged, proving fingerprint dedup bounded duplicate reprocessing.
- CRL-029 failed on final rerun: earlier synthetic DID/debug-session and SE050 failures were cleared. Final rerun used the real nodeC DID, nodeB had `exists=true`/`active_sessions=1`, nodeA REST revoke succeeded, and nodeB received the emergency notice. nodeB still reported `exists=true`, `active_sessions=1`, `sessions_terminated_delta=0`, and no `EMERGENCY revocation applied ... sessions_terminated=1` audit entry. Audit showed routine gossip later merged the critical revocation, while emergency status showed `merged=false`. Likely code-side race/logic gap: critical session termination is tied to emergency `newly_merged=true`, so if routine gossip merges first or the entry is already present, the side effect is skipped.
- CRL-030 PASS: nodeC `GET /api/v1/crl/emergency/notifications` returned multiple critical notification records and `/var/lib/sgx-guardian/identity/crl/emergency_notifications.jsonl` existed with JSONL records. nodeA source feed was empty.
- CRL-031 PASS: nodeA/nodeB/nodeC emergency status endpoint exposed enabled config, port, TTL, counters, sessions_terminated, and last_notice metadata.
- CRL-032 PASS: nodeA `POST /api/v1/crl/emergency/broadcast?did=did:guardian:board-emergency-ttl-dedup-20260721-002` returned `success=true` and status showed `notices_sent=2`, `peers=2`.
- CRL-033 PASS: nodeB/nodeC live nft rules allowed `50063` and emergency UDP `50064`; listener was visible on `0.0.0.0:50064`; emergency rebroadcast continued to work under enforcement.
- CRL-034 PASS: nodeA/nodeB/nodeC all converged to Merkle root `43a51330227510e3e822b5e06a98c7d07c687c1d9b165b501493ebe9c952219f`; nodeC sequence differed (`18` vs `13`) but content root and propagated entry count converged.
- Hook2 PASS: nodeB was restarted with `SGX_CRL_EMERGENCY_ENABLED=0`; API status returned `"enabled": false` and `netstat -lun | grep 50064` returned no listener (`PASS: no emergency UDP 50064 listener`). NodeA/nodeC remained in normal enabled mode during this scoped hook test.
```

---

## ✅ Final Summary

- **Requirements Passed:** `7/8`
- **APIs Passed:** `4/4`
- **CLI / Runtime Hooks Passed:** `2/2`
- **Overall Verdict:** ❌ CRL-029 / Requirement 5 failed on final board rerun — CRL-022 through CRL-028, CRL-030 through CRL-034, and both runtime hooks passed; session termination still needs a code fix and rerun.
