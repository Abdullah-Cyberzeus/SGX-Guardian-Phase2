# CRL Gossip Protocol — Verification Log
**Boards:** nodeA (192.168.50.101/103) · nodeB (192.168.50.115) · nodeC (192.168.50.248) — iMX8MP (ARM64) | **Date:** ____ | **Tester:** Asad Ali
**Test tag:** CRL-series (CRL-011 – CRL-021) | **Plan:** `CRL_Gossip_Protocol_Complete_Plan.md`

---

## 📌 Task Description

> Implement epidemic-style gossip protocol for decentralized CRL propagation without central authority. Each Guardian maintains local CRL copy. Periodically (every 1-5 minutes), Guardian randomly selects peer and exchanges CRL updates. Peer merges received revocations into local CRL, then forwards to other peers. Uses probabilistic flooding with anti-entropy mechanisms. Track which peers received each revocation in "peers_notified" list. Mark CRL entry as "propagated" after reaching threshold (e.g., 80% of Circle). Achieves eventual consistency across all Circle members even with network partitions.

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
   - Kya gossip listener up hai (`ss -ltn | grep 50063`)?
   - Kya peer DID Documents sync ho chuke hain (`./sgx-pa-cli diddoc peers`)? — fresh boot pe 30–60 sec lag sakta hai
   - Kya interval ka wait kiya (default 60 s + jitter → 2 rounds tak ~2.5 min)? Ya `POST /crl/gossip/trigger` use karo
   - Alternate command se dobara try karo
2. **Sirf tab `❌` lagao** jab fully confirm ho jaye ke issue code side ka hai, command side ka nahi
3. **`❌` lagane ke saath ye bhi likho:**
   - Konsi file/function mein likely issue hai (e.g. `src/crl/gossip/engine.rs::handle_inbound`) (cross-check khud bhi karo — issue doosri file mein bhi ho sakta hai)
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

## ⚡ Test Setup (run once before Requirement 1)

```bash
# Har board pe — old process band, naya binary deploy, phir start:
pkill -f sgx_guardian_client || true
# (scp new binary here)
export SGX_CRL_GOSSIP_INTERVAL_SECS=15    # test accelerator (production default 60 s; spec window 1–5 min)
./sgx_guardian_client nodeA               # nodeB / nodeC on their boards

# Handy variables (adjust overlay IPs per actual allocation):
NODEA_OVERLAY=192.168.100.1
SELF_DID=$(jq -r .did /var/lib/sgx-guardian/identity/did.json)
NODEB_DID=$(ssh root@192.168.50.115 "jq -r .did /var/lib/sgx-guardian/identity/did.json")
NODEC_DID=$(ssh root@192.168.50.248 "jq -r .did /var/lib/sgx-guardian/identity/did.json")
```

> **Note:** Propagation tests dummy target DIDs use karte hain (e.g. `did:guardian:gossiptest001`) — **kabhi bhi nodeB/nodeC ka REAL DID revoke mat karo** propagation tests mein, warna woh node gossip mesh se exclude ho jayega (by design). Real-DID revocation sirf CRL-021 (exclusion test) mein hota hai, aur end pe `unrevoke` se restore hota hai.

---

## ⏳ Requirement 1 — [ ] Each Guardian maintains local CRL copy, no central authority

> Har node apni local CRL copy rakhta hai aur har node gossip listener (50063) chalata hai — nodeA koi special hub nahi hai.

**Commands (run on ALL THREE boards):**
```bash
ls -la /var/lib/sgx-guardian/identity/crl/
jq '{sequence, merkle_root, entries: (.entries | length)}' /var/lib/sgx-guardian/identity/crl/crl.json
ss -ltn | grep 50063 || netstat -ltn | grep 50063
grep -a "CRL gossip engine started" /var/log/sgx-guardian/audit-$(hostname | grep -o 'node.')*.log | tail -1
pgrep -f sgx_guardian_client
```

**Expected:**
```
crl.json present on all 3 nodes (independent local copies)
0.0.0.0:50063 LISTEN on ALL THREE nodes (symmetric — every node is client + server)
audit: "CRL gossip engine started port=50063 interval_secs=15 threshold_pct=80"
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

---

## ⏳ Requirement 2 — [ ] Periodic rounds every 1–5 minutes with RANDOM peer selection

> Round task interval pe fire karta hai (default 60 s, test accel 15 s), har round ek random peer choose hota hai.

**Commands (nodeA):**
```bash
grep -a "CRL gossip round" /var/log/sgx-guardian/audit-nodeA.log | tail -6
# Timestamps ka gap ≈ interval hona chahiye; peer= field alternate hona chahiye (kabhi B, kabhi C)
grep -a "CRL gossip round" /var/log/sgx-guardian/audit-nodeA.log | grep -o "node=node[A-Z]" | sort | uniq -c
```

**Expected:**
```
Consecutive round entries ~interval seconds apart (± jitter, up to +20%)
Both nodeB and nodeC appear as chosen peers over multiple rounds (randomness)
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

---

## ⏳ Requirement 3 — [ ] Peer merges received revocations into local CRL

> nodeA pe issue ki gayi revocation — bina B/C pe koi command chalaye — dono peers ki local CRL mein merge ho jati hai.

**Commands:**
```bash
# nodeA — issue revocation for a DUMMY target:
./sgx-pa-cli crl revoke --did did:guardian:gossiptest001 --reason compromised --severity critical --note "CRL-013"
date

# Wait ≤ 2 intervals (ya instant: curl -s -X POST http://localhost:8443/api/v1/crl/gossip/trigger)

# nodeB AND nodeC (no revoke command was ever run here):
./sgx-pa-cli crl check --did did:guardian:gossiptest001
grep -a "CRL gossip merged revocation" /var/log/sgx-guardian/audit-node?.log | tail -2
```

**Expected:**
```
nodeB + nodeC: "revoked": true with full entry (original issuer signature intact)
audit on B/C: CRL gossip merged revocation revoked_did=did:guardian:gossiptest001 ... via_peer=<did>
severity=critical merge → audit severity Critical (tamper-evident chain entry)
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

---

## ⏳ Requirement 4 — [ ] Forwards to other peers (transitive epidemic relay)

> Revocation ek intermediate node ke through aage travel karti hai — direct source contact ke baghair.

**Commands:**
```bash
# 1. nodeC ko band karo:
ssh root@192.168.50.248 "pkill -f sgx_guardian_client"

# 2. nodeA pe new revocation:
./sgx-pa-cli crl revoke --did did:guardian:gossiptest002 --reason stolen --severity critical --note "CRL-014 relay"

# 3. Wait until nodeB has it:
ssh root@192.168.50.115 "./sgx-pa-cli crl check --did did:guardian:gossiptest002"   # → true

# 4. Ab nodeA band karo (source OFF), phir nodeC start karo:
pkill -f sgx_guardian_client            # on nodeA
ssh root@192.168.50.248 "cd <deploy_dir> && ./sgx_guardian_client nodeC" &

# 5. nodeC can ONLY learn from nodeB now:
ssh root@192.168.50.248 "./sgx-pa-cli crl check --did did:guardian:gossiptest002"
ssh root@192.168.50.248 "grep -a 'via_peer' /var/log/sgx-guardian/audit-nodeC.log | tail -1"

# 6. Restore: restart nodeA
./sgx_guardian_client nodeA
```

**Expected:**
```
nodeC: "revoked": true — learned via nodeB (via_peer = nodeB's DID), source nodeA was OFFLINE
Proves A → B → C epidemic forwarding, not hub-and-spoke
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

---

## ⏳ Requirement 5 — [ ] Probabilistic flooding + anti-entropy mechanisms

> (a) Converged state = cheap no-op heartbeat (equal fingerprint sets), (b) divergent state self-heals via full-set diff, (c) jitter rounds ko desynchronize karta hai.

**Commands:**
```bash
# (a) Converged no-op: sab nodes converged hone ke baad —
curl -s -X POST http://localhost:8443/api/v1/crl/gossip/trigger | python3 -m json.tool
# → merged: 0, pushed: 0 (anti-entropy fast path; ack phir bhi hota hai)

# (b) Merkle-root diff drives sync: audit se confirm karo ke jab roots differ karte
#     the tab entries move hui, equal hone ke baad merged=0 pushed=0:
grep -a "CRL gossip round" /var/log/sgx-guardian/audit-nodeA.log | tail -8

# (c) Jitter: teeno nodes ke round timestamps compare karo — perfectly aligned nahi honge:
for h in "" "root@192.168.50.115" "root@192.168.50.248"; do
  ${h:+ssh $h} grep -a "'CRL gossip round'" /var/log/sgx-guardian/audit-node?.log 2>/dev/null | tail -2
done
```

**Expected:**
```
(a) {"merged": 0, "pushed": 0, "success": true, ...}
(b) Earlier rounds show merged>0/pushed>0 while diverged; later rounds merged=0 pushed=0
(c) Round times across nodes offset by random jitter (never lock-step)
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

---

## ⏳ Requirement 6 — [ ] `peers_notified` tracking per entry

> Har entry track karti hai kin peers ne receive/ack kiya (DID list).

**Commands (nodeA, after ≥1 exchange with each peer):**
```bash
curl -s http://localhost:8443/api/v1/crl/list | python3 -c "
import json,sys
for e in json.load(sys.stdin)['entries']:
    print(e['revoked_did'], '| peers_notified:', e['peers_notified'], '| propagated:', e['propagated'])"
# Cross-check raw file:
jq '.entries[] | {revoked_did, peers_notified, propagated}' /var/lib/sgx-guardian/identity/crl/crl.json
```

**Expected:**
```
Each entry lists the DIDs of nodeB and nodeC after exchanges with both
peers_notified is LOCAL bookkeeping (remote copies ki values ingest pe reset hoti hain — zero-trust)
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

---

## ⏳ Requirement 7 — [ ] `propagated = true` at 80% Circle threshold

> 3-node Circle: other_members = 2 → threshold_count = ceil(0.8 × 2) = **2** → dono peers ke ack ke baad flag flip.

**Commands (nodeA):**
```bash
curl -s http://localhost:8443/api/v1/crl/gossip/status | python3 -m json.tool | grep -E '"other_members"|"threshold_pct"|"threshold_count"|"propagated"|"entries"'
grep -a "CRL entry propagated" /var/log/sgx-guardian/audit-nodeA.log | tail -3
jq '[.entries[] | select(.propagated == true)] | length' /var/lib/sgx-guardian/identity/crl/crl.json
```

**Expected:**
```
"other_members": 2, "threshold_pct": 80, "threshold_count": 2
audit: "CRL entry propagated id=urn:uuid:... threshold=2" (fires exactly after 2nd distinct peer ack)
propagated=true persists in crl.json
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

---

## ⏳ Requirement 8 — [ ] Eventual consistency across network partitions

> Partitioned node wapas aane pe missed revocations anti-entropy se automatically converge karta hai — Merkle roots teeno nodes pe identical.

**Commands:**
```bash
# 1. nodeC ko 5+ min band rakho; is dauran nodeA pe 2 revocations issue karo:
ssh root@192.168.50.248 "pkill -f sgx_guardian_client"
./sgx-pa-cli crl revoke --did did:guardian:gossiptest004 --reason compromised --severity critical
./sgx-pa-cli crl revoke --did did:guardian:gossiptest005 --reason policy_violation --severity high
sleep 300

# 2. nodeC restart → sirf wait karo (koi manual sync command NAHI):
ssh root@192.168.50.248 "cd <deploy_dir> && ./sgx_guardian_client nodeC" &
sleep 60   # ≤ 2 intervals

# 3. Convergence — teeno nodes pe:
./sgx-pa-cli crl root
ssh root@192.168.50.115 "./sgx-pa-cli crl root"
ssh root@192.168.50.248 "./sgx-pa-cli crl root"
ssh root@192.168.50.248 "./sgx-pa-cli crl check --did did:guardian:gossiptest004"

# 4. Restart-persistence (CRL-019): nodeA restart, state survive kare:
pkill -f sgx_guardian_client && sleep 3 && ./sgx_guardian_client nodeA & 
sleep 8 && ./sgx-pa-cli crl check --did did:guardian:gossiptest004
```

**Expected:**
```
Identical merkle_root hex string on all three nodes
nodeC has BOTH missed revocations post-rejoin, zero manual commands
Revoked state + propagated flags survive daemon restart (disk-backed)
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

---

## ⏳ Requirement 9 — [ ] Decentralized — works without any central authority

> (a) MEMBER node (nodeB) se issue hui revocation bhi propagate hoti hai; (b) nodeA (CA) completely OFF hone pe bhi B ↔ C gossip chalti rehti hai.

**Commands:**
```bash
# (a) Member-issued revocation on nodeB (member rules: security-critical reason + critical/high severity):
ssh root@192.168.50.115 "./sgx-pa-cli crl revoke --did did:guardian:gossiptest006 --reason compromised --severity high --note 'CRL-020 member'"
sleep 60
./sgx-pa-cli crl check --did did:guardian:gossiptest006                       # nodeA
ssh root@192.168.50.248 "./sgx-pa-cli crl check --did did:guardian:gossiptest006"  # nodeC

# (b) CA down, mesh alive:
pkill -f sgx_guardian_client        # nodeA OFF
ssh root@192.168.50.115 "grep -a 'CRL gossip' /var/log/sgx-guardian/audit-nodeB.log | tail -3"
ssh root@192.168.50.248 "grep -a 'CRL gossip' /var/log/sgx-guardian/audit-nodeC.log | tail -3"
# → fresh B↔C round entries with nodeA offline
./sgx_guardian_client nodeA         # restore
```

**Expected:**
```
(a) Member-issued entry revoked:true on nodeA AND nodeC (owner/CA involvement zero)
(b) B and C keep exchanging rounds while nodeA is down (timestamps during the outage window)
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

---

# 🔌 API Verification — New Endpoints

## ⏳ API 1 — [ ] GET `/api/v1/crl/gossip/status`

**Command:**
```bash
curl -s http://localhost:8443/api/v1/crl/gossip/status | python3 -m json.tool
```

**Expected:**
```json
{
    "enabled": true,
    "port": 50063,
    "interval_secs": 15,
    "threshold_pct": 80,
    "self_did": "did:guardian:...",
    "circle_id": "guardian-circle-alpha",
    "other_members": 2,
    "threshold_count": 2,
    "sequence": 4,
    "merkle_root": "hex-sha256-root",
    "entries": 3,
    "propagated": 3,
    "rounds_initiated": 12,
    "rounds_served": 9,
    "entries_merged": 3,
    "last_round": {"direction": "initiated", "peer_did": "...", "peer_node": "nodeB", "merged": 0, "sent": 0, "merkle_root": "...", "at": "2026-..."}
}
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

## ⏳ API 2 — [ ] POST `/api/v1/crl/gossip/trigger`

**Command:**
```bash
curl -s -X POST http://localhost:8443/api/v1/crl/gossip/trigger | python3 -m json.tool
```

**Expected:**
```json
{
    "success": true,
    "peer_did": "did:guardian:...",
    "peer_node": "nodeB",
    "merged": 0,
    "pushed": 1,
    "peer_merged": 1,
    "merkle_root": "hex-sha256-root",
    "newly_propagated": [],
    "message": "gossip round completed"
}
```
**Note:** Agar peers abhi sync nahi hue (fresh boot) to 500 `no active gossip peers yet` aa sakta hai — 60 sec wait karke retry (DID doc pull loop 30 s).

**Result:**
```
(paste output)
```

**Verdict:** ⏳

## ⏳ API 3 — [ ] Security — tampered entry rejected (signature re-verification)

> nodeB se ek tampered entry push karte hain (severity flip → issuer signature invalid). nodeA usay reject kare, merge NA kare.

**Command (run ON nodeB, targeting nodeA overlay IP):**
```bash
python3 - <<'EOF'
import json, socket
self_did = json.load(open('/var/lib/sgx-guardian/identity/did.json'))['did']
crl = json.load(open('/var/lib/sgx-guardian/identity/crl/crl.json'))
entry = dict(crl['entries'][0])
entry['severity'] = 'low' if entry['severity'] != 'low' else 'high'   # TAMPER -> proof breaks
req  = {"kind":"crl_sync_request","circle_id":crl['circle_id'],"sender_did":self_did,
        "sequence":0,"merkle_root":"","fingerprints":[]}
push = {"kind":"crl_sync_push","entries":[entry]}
s = socket.create_connection(("192.168.100.1", 50063), timeout=10)   # NODEA_OVERLAY
f = s.makefile('rw')
f.write(json.dumps(req)+"\n");  f.flush(); print("RESPONSE:", f.readline().strip()[:160])
f.write(json.dumps(push)+"\n"); f.flush(); print("ACK:", f.readline().strip())
EOF

# On nodeA:
grep -a "CRL gossip rejected entry" /var/log/sgx-guardian/audit-nodeA.log | tail -1
./sgx-pa-cli crl root    # root UNCHANGED by the tampered push
```

**Expected:**
```
ACK: {"kind":"crl_sync_ack","merged":0,...}
nodeA audit: "CRL gossip rejected entry urn:uuid:... : invalid proof ..."
Merkle root unchanged — tampered data never entered the CRL
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

## ⏳ API 4 — [ ] Revoked peer excluded both directions (CRL-021)

**Commands (nodeA):**
```bash
./sgx-pa-cli crl revoke --did "$NODEC_DID" --reason compromised --severity critical --note "CRL-021 exclusion"
sleep 60
curl -s http://localhost:8443/api/v1/crl/gossip/status | python3 -m json.tool | grep other_members   # 2 → 1
grep -a "CRL gossip rejected sender" /var/log/sgx-guardian/audit-nodeA.log | tail -1                  # C's inbound rejected
grep -a "node=nodeC" /var/log/sgx-guardian/audit-nodeA.log | tail -1                                  # no NEW dials to C

# RESTORE (Owner-only) — warna nodeC permanently excluded rahega:
curl -s -X POST http://localhost:8443/api/v1/crl/unrevoke -H "Content-Type: application/json" -d "{\"did\":\"$NODEC_DID\"}" | python3 -m json.tool
```

**Expected:**
```
other_members drops 2 → 1 (threshold_count recomputes to 1)
nodeC inbound: "CRL gossip rejected sender=<C did>: sender is revoked"
After unrevoke: other_members back to 2, gossip with C resumes
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

---

## 🗺️ Test-Tag Mapping (CRL-series continuation)

| Tag | What it proves | Section above |
|---|---|---|
| CRL-011 | Local copy + symmetric listener on all nodes | Req 1 |
| CRL-012 | Periodic 1–5 min rounds, random peer | Req 2 |
| CRL-013 | Merge of received revocations | Req 3 |
| CRL-014 | Transitive forwarding (A→B→C, source offline) | Req 4 |
| CRL-015 | Anti-entropy no-op + self-heal + jitter | Req 5 |
| CRL-016 | `peers_notified` tracking | Req 6 |
| CRL-017 | `propagated` at 80 % threshold | Req 7 |
| CRL-018 | Partition rejoin convergence (root parity) | Req 8 |
| CRL-019 | Persistence across daemon restart | Req 8 step 4 |
| CRL-020 | Decentralized: member-issued + CA-down mesh | Req 9 |
| CRL-021 | Revoked-peer exclusion + tamper rejection | API 3 + API 4 |

---

## ⚙️ Known Issue Placeholders (fill during testing)

### Issue 1 — ____
```
(symptoms / root cause / fix)
```

---

## 🧰 Emergency & Debug Commands

```bash
# Kill-switch (no rebuild): restart binaries with gossip OFF
SGX_CRL_GOSSIP_ENABLED=0 ./sgx_guardian_client nodeA

# Listener alive?
ss -ltn | grep 50063
# Raw port reachability from a peer (over overlay):
timeout 3 bash -c "echo > /dev/tcp/192.168.100.1/50063" && echo OPEN || echo CLOSED

# Full gossip trail on a node:
grep -a "CRL gossip" /var/log/sgx-guardian/audit-nodeA.log | tail -20

# Peer directory sanity (gossip candidates come from here):
./sgx-pa-cli diddoc peers

# If enforcement policy was applied and gossip died → confirm allow rule exists:
nft list table inet sgx_guardian 2>/dev/null | grep 50063

# Suricata inline-block false positive (known ICMP test-rule issue) — if a board got blocked:
nft flush chain inet sgx_threat input
rm -f /var/lib/sgx-guardian/threat/blocked_ips.json

# Reset gossip test state on ALL nodes (removes ONLY dummy test entries via unrevoke, Owner on nodeA):
for d in gossiptest001 gossiptest002 gossiptest004 gossiptest005 gossiptest006 gossipsmoke01; do
  curl -s -X POST http://localhost:8443/api/v1/crl/unrevoke -H "Content-Type: application/json" -d "{\"did\":\"did:guardian:$d\"}"
done
```

**Timing cheat-sheet:** default interval 60 s → cross-cohort convergence typically ≤ 2–3 min · `SGX_CRL_GOSSIP_INTERVAL_SECS=15` → ≤ 45 s · `POST /crl/gossip/trigger` → seconds.
