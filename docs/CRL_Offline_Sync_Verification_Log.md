# CRL Offline Revocation Sync — Verification Log
**Boards:** nodeA (192.168.1.157) · nodeB (192.168.1.195) · nodeC (192.168.1.196) — iMX8MP (ARM64) | **Date:** `2026-07-22` | **Tester:** Asad Ali
**Test tag:** CRL-series (CRL-033 – CRL-043) | **Plan:** `CRL_Offline_Revocation_Sync_Complete_Plan.md`

---

## 📌 Task Description

> Implement offline revocation queue for Guardians operating in disconnected environments (tactical ops, remote locations, satellite with intermittent connectivity). When Guardian goes offline, queue outgoing revocations locally. Track pending revocations with retry counter and timestamps. When connectivity restored, synchronously push queued revocations to peers. Fetch missed revocations from peers by comparing CRL version vectors. Resolve conflicts using timestamp-based "last writer wins" or signature-based trust hierarchy. Ensures Guardians can revoke compromised peers even when isolated.

---

## 📋 How to Use This File

**Jab bhi koi Requirement ya API verify ho jaye (PASS):**
1. `[ ]` ko `[x]` karo aur `## ⏳` ko `## ✅` kar do
2. **Commands:** section mein woh exact command likhna jo run kiya
3. **Result:** section mein terminal output paste karna
4. **Verdict:** ek line mein confirm karna — kya pass hua

**Jab koi Requirement ya API FAIL ho:**
1. **Pehle command side verify karo** — command galat bhi ho sakti hai, code galat nahi bhi ho sakta:
   - Kya teeno nodes chal rahe hain (`pgrep -f sgx_guardian_client`)?
   - Kya offline sync banner aaya start pe (`grep "CRL-OFFLINE sync starting"`)?
   - Kya sync interval ka wait kiya (default 20 s; ya `SGX_CRL_OFFLINE_SYNC_INTERVAL_SECS=8` set karke accelerate karo; ya `POST /crl/offline/sync` se instant cycle chalao)?
   - Kya gossip pehle se kaam kar raha hai (offline sync usi ke exchange pe depend karta hai — pehle `POST /crl/gossip/trigger` try karke dekho gossip theek hai)?
   - Alternate command se dobara try karo
2. **Sirf tab `❌` lagao** jab fully confirm ho jaye ke issue code side ka hai, command side ka nahi
3. **`❌` lagane ke saath ye bhi likho:**
   - Konsi file/function mein likely issue hai (e.g. `src/crl/offline/sync.rs::run_cycle`) (cross-check khud bhi karo — issue doosri file mein bhi ho sakta hai, e.g. gossip `run_round_once`)
   - Exact error message jo aaya
   - Kya try kiya aur kya nahi chala

**⚠️ Common mistakes jo dobara na karein:**
- **DID hamesha poora `did:guardian:...` prefix ke sath likhna** — truncated ID galat (non-existent) DID check karega, result misleading hoga.
- **`<...>` angle brackets literally mat likhna** — placeholder markers hain, shell mein redirection operators.
- **Propagation/offline tests mein hamesha DUMMY target DIDs use karo** (e.g. `did:guardian:offline-test-001`) — real nodeB/nodeC DID revoke karoge to woh node mesh se exclude ho jayega aur sync tests kharab honge.
- **Entry IDs / pending IDs hamesha CURRENT session ke run se lena** — har fresh test run mein naye UUIDs bante hain.

**Requirements count ke baare mein:**
- Requirements task description ke distinct verifiable claims se derive hoti hain — fixed count nahi.
- Artificially pad mat karo, koi genuine requirement miss bhi mat karo.

**Symbols:** `✅` = Verified and passed · `❌` = Confirmed code-side failure (command side ruled out) · `⏳` = Not yet tested

---

## ⚡ Test Setup (run once before Requirement 1)

```bash
# Har board pe: purana process band, naya binary deploy, phir start (offline sync accelerated):
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

> **Simulating "offline":** shared LAN pe pura network kaatna mushkil hai. Do practical tareeqe: (a) issue a revocation for a **dummy** DID on a node and observe it sit in `pending/` until sync cycles flush it (delivery to peers); (b) for a true partition, `pkill` a node, issue on another, then restart the killed node and watch it fetch missed revocations. Dono neeche cover hain.
>
> **Board correction from actual testing (`2026-07-22`):** nodeA ko startup se pehle OFF mat karo. nodeA CA / registry-sync / lighthouse role de raha hai; nodeC ko clean bootstrap ke liye nodeA ka reachable hona zaroori nikla. `Requirement 3/4` ke liye bhi preferred board-safe method yehi hai ke `nodeA` ON rahe aur hum `nodeC` par sirf CRL sync ports temporarily block karke offline condition simulate karein.
>
> **Runtime observation (`2026-07-22`):** nodeC foreground log ne nodeB ko `192.168.4.3:50052` se load kiya, jab ke board test inventory me nodeB `192.168.1.195` diya gaya hai. Yeh current nodeA↔nodeC tests ko block nahi karta, lekin nodeB-dependent requirements (Req 4–6) se pehle runtime config cross-check karna chahiye.

## ⚡ Fast Grouped Run Order

### Block 1 — Req 1 + Req 2 + API 1 + API 2

**Goal:** nodeA ko ON rakh kar nodeC pe local queue + retry metadata + offline REST observability prove karna:
- pending queue persist hoti hai
- attempts / timestamps update hote hain
- `/crl/offline/status` aur `/crl/offline/pending` dono expected shape return karte hain

**Node A (192.168.1.157):**
```bash
# nodeA ON rehna chahiye; isi terminal me foreground run best raha
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
- existing pending entries me attempts >= 1
- queued_at fixed rehta hai
- last_attempt_at populate hota hai; daemon log me next cycles pe attempt bump nazar aata hai

API 1 PASS:
- GET /api/v1/crl/offline/status returns enabled/online/pending/sync counters

API 2 PASS:
- GET /api/v1/crl/offline/pending returns count + pending[] with attempts/timestamps/parked
```

> **Note:** yeh block intentionally full-isolation proof nahi hai; Requirement 3 ke liye corrected nodeA/nodeC boot sequence alag se follow karo.

---

## ✅ Requirement 1 — [x] Locally queue outgoing revocations (pending queue persists)

> Jab koi revocation issue hoti hai, woh local `pending/` queue mein persist hoti hai (retry + timestamp metadata ke saath), aur `crl.json` mein bhi immediately aa jati hai.

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
pending/urn_uuid_<...>.json file present
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

**Verdict:** ⏳ Blocked / retry required — this attempt did not prove Requirement 1 because the local revoke never succeeded. The first blocker is board-side SE050 signing/session failure (`No open session`), so no CRL entry was created and no pending queue file could exist yet. The REST checks are also not usable from this attempt because `/crl/offline/*` returned empty output and `jq` is not available on the board.

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

**Recovery verdict:** ✅ NodeC environment recovered enough for a clean Requirement 1 retry. The original blocker was board/runtime state, not yet a confirmed offline-sync code defect.

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

**Retry verdict:** ⏳ Partial / retry required — Requirement 1 is closer to proven now because the local CRL entry was successfully created and remained `propagated:false`, but the queue was checked too early for the CLI self-reconcile path and the REST API was not yet returning usable JSON at the moment of inspection. Re-run once the daemon is fully healthy, then wait one sync cycle (or trigger `POST /crl/offline/sync`) before checking `pending/`.

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

**Retry verdict:** ⏳ Still blocked — Requirement 1 remains unproven. This retry did not create a CRL entry or pending queue item because the NodeC daemon exited before REST became healthy and the CLI revoke again failed with an SE050 session error. At this point the blocker is board runtime stability / SE050 session state, not yet a confirmed offline-sync logic defect.

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

**Verdict:** ✅ PASS — Requirement 1 is now proven on-board. The blocker was not offline-sync logic; the blocker was test topology. Once nodeA stayed ON for nodeC bootstrap, the local REST revoke immediately created a CRL entry, persisted a pending queue file, and exposed the same item through `/api/v1/crl/offline/pending`.

---

## ✅ Requirement 2 — [x] Track pending revocations with retry counter and timestamps

> Har pending entry apna `attempts` counter aur `queued_at`/`last_attempt_at` timestamps track karti hai; har sync cycle pe attempt bump hota hai (jab tak delivered na ho).

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

---

## ⏳ Requirement 3 — [ ] Queue works when offline; nothing lost while isolated

> Jab koi peer reachable nahi (offline), sync cycle no-op karta hai aur queue persist rehti hai — koi revocation lost nahi hoti. Guardian isolated hone pe bhi compromised peer ko revoke kar sakta hai.

**Commands:**
```bash
# nodeA ON rakho (CA / lighthouse / relay ke liye). nodeB band reh sakta hai.
# nodeC par sirf CRL sync channels block karo taake overlay/CA alive rahe but offline-sync isolated ho jaye.
iptables -I OUTPUT -p tcp --dport 50063 -j REJECT
iptables -I INPUT  -p tcp --sport 50063 -j REJECT
iptables -I OUTPUT -p udp --dport 50064 -j REJECT
iptables -I INPUT  -p udp --sport 50064 -j REJECT
sleep 12   # nodeC ka agla cycle → offline detect

# nodeC pe (isolated) revoke + status:
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

**Verdict:** ⏳ Partial / retry required — Requirement 3 is now much closer: the corrected port-block method definitively proved the real isolated state (`"online": false`) and also proved that pending revocations are retained while isolated (nothing silently dropped). The only missing proof is "fresh local revoke while isolated" for this exact offline run, and that failed for a board/runtime reason outside offline-sync: SE050 session/tamper state blocked signing before a new CRL entry could be issued.

---

## ✅ Requirement 4 — [x] On connectivity restored, synchronously push queued revocations to peers

> Jab connectivity wapas aati hai (offline→online transition), sync loop reconnect detect karta hai aur queued revocations ko peers tak push karta hai (gossip exchange ke through), phir delivery confirm hone pe dequeue.

**Commands (continue from Requirement 3):**
```bash
# nodeC par block hatana = connectivity restore for offline-sync
iptables -D OUTPUT -p tcp --dport 50063 -j REJECT
iptables -D INPUT  -p tcp --sport 50063 -j REJECT
iptables -D OUTPUT -p udp --dport 50064 -j REJECT
iptables -D INPUT  -p udp --sport 50064 -j REJECT
sleep 12

# deterministic cycle chalao + status check
curl -s -X POST http://localhost:8443/api/v1/crl/offline/sync | python3 -m json.tool
curl -s http://localhost:8443/api/v1/crl/offline/status | python3 -m json.tool

# audit + peer verification
grep -aE 'connectivity RESTORED|flush attempt|cycle complete' /var/log/sgx-guardian/audit-nodeC.log | tail -20
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

---

## ⏳ Requirement 5 — [ ] Fetch missed revocations from peers by comparing CRL version vectors

> Jab node offline tha, uss dauran doosre nodes pe issue hui revocations ko reconnect pe fetch karta hai — CRL version vectors (sequence/merkle_root) compare karke. Per-peer sync-state observable hai.

**Commands:**
```bash
# nodeC band karo; is dauran nodeA pe 2 revocations issue karo (nodeC ko yeh MISS hongi):
ssh root@192.168.1.196 "pkill -f sgx_guardian_client"
/home/root/sgx-pa-cli crl revoke --did did:guardian:offline-test-003 --reason compromised --severity critical --note "CRL-037 missed"
/home/root/sgx-pa-cli crl revoke --did did:guardian:offline-test-004 --reason lost --severity high --note "CRL-037 missed"
sleep 5

# nodeC wapas start → sirf wait (koi manual pull command NAHI):
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

**Verdict:** ⏳ Retry required — this Requirement 5 run did not actually test fetch-missed behavior because the two source revocations on nodeA failed before creation. The current blocker is board-side SE050 session state on nodeA, not yet an offline-sync fetch logic defect.

---

## ⏳ Requirement 6 — [ ] Resolve conflicts (deterministic) — CRL converges, no split-brain

> Agar do nodes independently same DID revoke karein (offline dauran), reconnect pe conflict deterministically resolve hota hai (earliest-timestamp wins, shared gossip rule) — teeno nodes ka Merkle root identical.

**Commands:**
```bash
# nodeB aur nodeC dono ko band karke, dono pe SAME dummy DID revoke karo (different timestamps):
ssh root@192.168.1.195 "pkill -f sgx_guardian_client"
ssh root@192.168.1.196 "pkill -f sgx_guardian_client"
ssh root@192.168.1.195 "cd /home/root && ./sgx_guardian_client nodeB & sleep 5; /home/root/sgx-pa-cli crl revoke --did did:guardian:conflict-test-001 --reason compromised --severity high --note 'B first'"
sleep 3
ssh root@192.168.1.196 "cd /home/root && ./sgx_guardian_client nodeC & sleep 5; /home/root/sgx-pa-cli crl revoke --did did:guardian:conflict-test-001 --reason stolen --severity high --note 'C later'"
sleep 40   # let gossip + offline sync converge across all three

# Convergence check — teeno nodes:
/home/root/sgx-pa-cli crl root
ssh root@192.168.1.195 "/home/root/sgx-pa-cli crl root"
ssh root@192.168.1.196 "/home/root/sgx-pa-cli crl root"
# The surviving entry (earliest timestamp) same on all three:
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
The same single entry survives everywhere (earliest timestamp wins — deterministic)
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

**Verdict:** ⏳ Partial / retry required — the actual conflict scenario was created successfully and the conflict winner now matches across all boards (`urn:uuid:9a09277e-41c4-4bdb-a18e-7700991183df`, reason `stolen`). However, Requirement 6 is still not fully proven because full-root convergence has not happened: Boards A and B share the same `merkle_root`, while Board C still reports a different root even after a successful gossip-trigger round.

---

## ⏳ Requirement 7 — [ ] Retry budget + never silently drop (parking) + restart persistence

> Undelivered revocation retry hoti rehti hai; `MAX_RETRIES` set ho to exhaust hone pe **parked** hoti hai (disk pe retained + audited, dropped NAHI). Queue restart survive karti hai.

**Commands:**
```bash
# nodeC pe MAX_RETRIES=2 ke saath, ek revocation aisi jo deliver na ho sake (peers band):
ssh root@192.168.1.157 "pkill -f sgx_guardian_client"; ssh root@192.168.1.195 "pkill -f sgx_guardian_client"
ssh root@192.168.1.196 "pkill -f sgx_guardian_client"
ssh root@192.168.1.196 "cd /home/root && SGX_CRL_OFFLINE_SYNC_INTERVAL_SECS=6 SGX_CRL_OFFLINE_MAX_RETRIES=2 ./sgx_guardian_client nodeC &"
ssh root@192.168.1.196 "/home/root/sgx-pa-cli crl revoke --did did:guardian:offline-test-005 --reason compromised --severity high --note 'CRL-039 park'"
sleep 30   # several cycles with no reachable peer
ssh root@192.168.1.196 "curl -s http://localhost:8443/api/v1/crl/offline/pending | python3 -m json.tool"   # attempts ≥ 2, parked:true

# Restart persistence: nodeC restart, pending survive kare:
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

**Verdict:** ⏳ Partial / likely code-side gap — this run proves isolated issuance, queue retention, and restart persistence through both disk and REST. It still does not prove retry-budget parking because attempts never incremented to the configured limit and `parked:true` never appeared. The remaining gap is now specific: fully offline/no-reachable-peer cycles keep the pending item but do not count attempts, and a propagated CRL entry can still have a stale pending file.

---

## ⏳ Requirement 8 — [ ] Self-reconcile queue from local state (covers CLI-issued + restart)

> Sync loop har cycle local `crl.json` reconcile karta hai: koi bhi locally-issued (`revoker_did == self`) aur `propagated == false` entry automatically pending ban jati hai — chahe woh CLI se issue hui ho (REST handler ke baghair).

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

**Verdict:** ⏳ Blocked / retry required — Requirement 8 remains untested. First recover nodeC SE050 CLI signing, then retry with a fresh DID and only evaluate self-reconcile after `crl.json` contains the local CLI-issued entry.

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
**Note:** Agar abhi koi pending nahi aur sab converged hai to `fetched`/`delivered` 0 honge (steady state) — yeh sahi hai. Pending hone pe `delivered` badhega.

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

**Verdict:** ✅ PASS — endpoint returned the expected deterministic cycle summary on-board after connectivity restore. `delivered` was `0` in this run, but that does not affect API correctness; it only means this specific cycle did not yet confirm queue delivery.

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

## ⚙️ Known Issue Placeholders (fill during testing)

### Issue 1 — ____
```
(symptoms / root cause / fix)
```

---

## 🧰 Emergency & Debug Commands

```bash
# Kill-switch (no rebuild): restart with offline sync OFF
SGX_CRL_OFFLINE_ENABLED=0 ./sgx_guardian_client nodeA

# Watch the offline sync trail:
grep -a "CRL offline\|CRL-OFFLINE\|connectivity RESTORED" /var/log/sgx-guardian/audit-nodeA.log | tail -20

# Inspect the queue + version vectors directly:
ls -la /var/lib/sgx-guardian/identity/crl/pending/
cat /var/lib/sgx-guardian/identity/crl/pending/*.json | python3 -m json.tool
cat /var/lib/sgx-guardian/identity/crl/sync_state.json | python3 -m json.tool

# Force one sync cycle immediately (instead of waiting for the interval):
curl -s -X POST http://localhost:8443/api/v1/crl/offline/sync | python3 -m json.tool

# Is gossip healthy? (offline sync rides the gossip exchange — check this first if fetch/flush stalls)
curl -s -X POST http://localhost:8443/api/v1/crl/gossip/trigger | python3 -m json.tool

# Manually clear a parked/stuck pending entry after operator review (dummy DIDs only):
rm -f /var/lib/sgx-guardian/identity/crl/pending/urn_uuid_<...>.json

# Reset offline test state (unrevoke dummy DIDs on nodeA/Owner):
for d in offline-test-001 offline-test-002 offline-test-003 offline-test-004 offline-test-005 offline-test-006 conflict-test-001; do
  curl -s -X POST http://localhost:8443/api/v1/crl/unrevoke -H "Content-Type: application/json" -d "{\"did\":\"did:guardian:$d\"}"
done
```

**Timing cheat-sheet:** default sync interval 20 s → reconnect flush within ~1 cycle · `SGX_CRL_OFFLINE_SYNC_INTERVAL_SECS=8` → faster · `POST /crl/offline/sync` → instant. Delivery confirmation needs gossip to reach the `propagated` threshold, so allow gossip a round or two after the push.
