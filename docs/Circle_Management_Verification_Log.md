# Circle-as-Comms Container + Invites — Verification Log
**Boards:** nodeA — owner (192.168.50.115) · nodeB — joiner (192.168.50.248) — iMX8MP (ARM64) | **Date:** ______ | **Tester:** Asad Ali
**Test tag:** CIRCLE-series (CIRCLE-001 – CIRCLE-009) | **Plan:** `Circle_Management_Complete_Plan.md`

---

## 📌 Task Description

> Implement Circle creation, editing, membership management, QR-based invitations, signed invite tokens, and member administration using DID/VC identity verification. A **Comms Circle** (many, new) rides the existing mesh and scopes chat/calls/files membership — distinct from the single **Mesh Circle** (read-only here) that drives Nebula/CRL/attestation. Members are added by **issuing a membership VC** scoped to the comms circle; removal is a **status-list revoke only** (NOT a CRL/mesh revoke). Join is a **mutual-proof** flow over the existing admin API — no new port. **Milestone-4 guard: CRL gossip / cert-bootstrap must remain untouched.**

---

## 📋 How to Use This File

**Jab bhi koi Requirement ya API verify ho jaye (PASS):**
1. `[ ]` ko `[x]` karo aur `## ⏳` ko `## ✅` kar do
2. **Commands:** section mein woh exact command likhna jo run kiya
3. **Result:** section mein terminal output paste karna
4. **Verdict:** ek line mein confirm karna — kya pass hua

**Jab koi Requirement ya API FAIL ho:**
1. **Pehle command side verify karo** — command galat bhi ho sakti hai, code galat nahi bhi ho sakta:
   - Kya dono nodes chal rahe hain (`pgrep -f sgx_guardian_client`)?
   - Kya admin API up hai dono pe (`curl -s http://localhost:8443/api/v1/health`)?
   - **Join test (CIRCLE-007) ke liye — kya nodeB, nodeA ki :8443 tak pohonch sakta hai?** `nft list ruleset | grep 8443` — **agar empty hai to join CHUP-CHAAP fail hoga** (gossip port wali same class ka bug)
   - Kya registry seed hua (`circles.json` — pehli `GET /circles` par seed hota hai)?
   - Member/CRUD test ke liye — kya caller **owner** hai? Non-owner ko `ensure_circle_owner` 403 dega (ye correct behavior hai, bug nahi)
   - Invite test ke liye — kya invite expire to nahi hua (default 24h)? owner_host reachable hai?
   - Alternate command / dobara try karo
2. **Sirf tab `❌` lagao** jab fully confirm ho jaye ke issue code side ka hai, command side ka nahi
3. **`❌` lagane ke saath ye bhi likho:**
   - Konsi file/function mein likely issue hai (e.g. `src/circle/store.rs` [seed/registry], `src/circle/invite.rs` [token/verify/replay], `src/circle/members.rs` [add/remove/role], `src/api/handlers/circle.rs::redeem` [6-step chain]) (cross-check khud bhi karo — issue doosri file mein bhi ho sakta hai)
   - Exact error message jo aaya
   - Kya try kiya aur kya nahi chala

**Requirements count ke baare mein:**
- Requirements ki count task description se derive hoti hai — fixed count number nahi hona chahiye
- Jitne distinct verifiable claims task description mein hain utni hi requirements banani hain
- Artificially pad mat karo aur koi genuine requirement miss bhi mat karo

**Symbols:**
- `✅` = Verified and passed
- `❌` = Confirmed code-side failure (command side fully ruled out)
- `⏳` = Not yet tested

---

## ⚡ Test Setup (run once before Requirement 1)

```bash
# Dono boards pe — old process band, naya binary deploy, phir start:
pkill -f sgx_guardian_client || true
# (scp new binary to both nodes)
./sgx_guardian_client nodeA      # owner  (192.168.50.115)
./sgx_guardian_client nodeB      # joiner (192.168.50.248)

# Handy variables (nodeA = owner):
API=http://localhost:8443/api/v1
OWNER_HOST=192.168.50.115
SELF_DID=$(jq -r .did /var/lib/sgx-guardian/identity/did.json)          # owner DID
NODEB_DID=$(ssh root@192.168.50.248 "jq -r .did /var/lib/sgx-guardian/identity/did.json" 2>/dev/null)  # real joiner DID
CIRCLE_DIR=/var/lib/sgx-guardian/identity/circles                       # circles.json + invites/
DUMMY_DID="did:guardian:DUMMYcircleTestOnly00000000000000000000000000"  # for add/remove tests

# ⚠️ PRE-FLIGHT (critical for the join flow, CIRCLE-007): owner's :8443 reachable P2P?
nft list ruleset | grep 8443     # empty => join dies silently under enforcement — fix before D5

# Trigger registry seed + confirm Mesh Circle present:
curl -s "$API/circles" | python3 -m json.tool
ls -l "$CIRCLE_DIR"
```

> **Notes:**
> - **Two kinds of circle.** The **Mesh Circle** (id `guardian-circle-alpha`) is read-only here (drives Nebula/CRL) — it **cannot be archived**. **Comms Circles** (`circle-<uuid>`) are what this feature creates.
> - **Dummy vs real DIDs.** Use `DUMMY_DID` for standalone add/remove/role tests (keeps the mesh clean). The **join flow (CIRCLE-007)** uses nodeB's **real** DID (it actually joins). Removing a comms-circle member is a **status-list revoke only** — it does **not** kick a device off the mesh, so even a real DID is safe to remove here.
> - **Milestone-4 guard.** Nothing in this feature may change CRL gossip behaviour — every test that mutates a circle also confirms `crl/list` / `crl/gossip/status` are unchanged.

---

## ⏳ Requirement 1 — [ ] Circle creation (comms circle) + Mesh Circle seeded

> Registry pehli read par **Mesh Circle** ko owner VC se seed karta hai. Operator ek naya **Comms Circle** create kar sakta hai — signed, atomically-written `circles.json` mein.

**Commands (nodeA / owner):**
```bash
# Mesh Circle seeded on first read:
curl -s "$API/circles" | python3 -c "import sys,json;d=json.load(sys.stdin);[print(c['kind'],c['circle_id'],c['name']) for c in d]"

# Create a comms circle:
CID=$(curl -s -X POST "$API/circles" -H 'content-type: application/json' \
  -d '{"name":"Ops Team","description":"CIRCLE-001 test"}' | python3 -c "import sys,json;print(json.load(sys.stdin)['circle_id'])")
echo "CID=$CID"

# On disk — signed registry:
python3 -c "import json;r=json.load(open('$CIRCLE_DIR/circles.json'));print('count:',len(r['circles']));print('has_proof:', 'proof' in r);print('seq:',r.get('sequence'))"
```

**Expected:**
```
GET /circles → Mesh circle present (kind=Mesh, id=guardian-circle-alpha), read-only
POST /circles → new comms circle (kind=Comms, id=circle-<uuid>), 201
circles.json: signed (proof present), sequence incremented
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

---

## ⏳ Requirement 2 — [ ] Circle editing (rename)

> Ek comms circle ka name/description `PATCH` se update hota hai; registry re-signed + persisted.

**Commands (nodeA / owner):**
```bash
curl -s -X PATCH "$API/circles/$CID" -H 'content-type: application/json' \
  -d '{"name":"Ops Team (Renamed)"}' | python3 -m json.tool
curl -s "$API/circles/$CID" | python3 -c "import sys,json;c=json.load(sys.stdin);print('name:',c['name'],'| updated_at:',c['updated_at'])"

# Restart → edit persists:
pkill -f sgx_guardian_client && sleep 3 && ./sgx_guardian_client nodeA &
sleep 8
curl -s "$API/circles/$CID" | python3 -c "import sys,json;print('name after restart:',json.load(sys.stdin)['name'])"
```

**Expected:**
```
PATCH → name updated, updated_at refreshed, registry re-signed
After restart → renamed name persists (atomic write)
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

---

## ⏳ Requirement 3 — [ ] Membership management (add + list via VC)

> Member add karna = uske comms-`circle_id` ke liye ek **membership VC issue** karna (pure VC reuse, no new crypto). List members role + lifecycle state ke saath.

**Commands (nodeA / owner — DUMMY_DID for a clean standalone test):**
```bash
# Add a member (issues a VC scoped to CID):
curl -s -X POST "$API/circles/$CID/members" -H 'content-type: application/json' \
  -d "{\"did\":\"$DUMMY_DID\",\"role\":\"Member\"}" | python3 -m json.tool

# List members with role + state:
curl -s "$API/circles/$CID/members" | python3 -c "import sys,json;[print(m['did'][:32],m.get('role'),m.get('state')) for m in json.load(sys.stdin)]"

# Confirm a VC was issued for this circle (not the mesh circle):
curl -s "$API/vc/issued" | python3 -c "import sys,json;[print(v['credentialSubject']['circleId']) for v in json.load(sys.stdin)]" | sort | uniq -c
```

**Expected:**
```
POST members → membership VC issued, subject=DUMMY_DID, circle_id=CID, role=Member
GET members → member listed, role=Member, state=Active (classify_vc_state)
Issued VCs include one for circle-<uuid> (comms), separate from guardian-circle-alpha (mesh)
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

---

## ⏳ Requirement 4 — [ ] Member administration + DID/VC authorization (non-owner 403)

> Role change = revoke + reissue. Authorization: har mutating route `ensure_circle_owner` gate se guzarti hai — **non-owner ko 403** milta hai (DID/VC identity verification).

**Commands:**
```bash
# Role change (owner):  Member -> Owner
curl -s -X PATCH "$API/circles/$CID/members/$DUMMY_DID" -H 'content-type: application/json' \
  -d '{"role":"Owner"}' | python3 -m json.tool
curl -s "$API/circles/$CID/members" | python3 -c "import sys,json;[print(m['did'][:20],m.get('role')) for m in json.load(sys.stdin)]"

# Authorization — a NON-OWNER node (nodeB) tries to mutate nodeA's circle → 403:
ssh root@192.168.50.248 "curl -s -o /dev/null -w '%{http_code}\n' -X POST http://$OWNER_HOST:8443/api/v1/circles/$CID/members -H 'content-type: application/json' -d '{\"did\":\"$DUMMY_DID\",\"role\":\"Member\"}'"
```

**Expected:**
```
PATCH role → status-list revoke of old VC + reissue with new role (Owner)
Non-owner mutation → HTTP 403 (ensure_circle_owner gate fires) — DID/VC-verified authorization
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

---

## ⏳ Requirement 5 — [ ] Signed invite tokens (expired / tampered / replayed / non-owner rejected)

> Invite token signed (ECDSA-P256), time-limited (default 24h, clamp 5min..30d), replay-protected (`max_uses`, default 1). Tampered/expired/replayed/non-owner-minted tokens **reject** hone chahiye. Permissions blindly token se nahi lete — re-derive + validate (no `vc:issue` escalation).

**Commands (nodeA / owner — mint, then negative cases):**
```bash
# Mint a single-use invite:
MINT=$(curl -s -X POST "$API/circles/$CID/invites" -H 'content-type: application/json' -d '{"role":"Member"}')
echo "$MINT" | python3 -m json.tool
TOKEN=$(echo "$MINT" | python3 -c "import sys,json;print(json.load(sys.stdin)['token_b64'])")

# --- Negative cases (these are UNIT tests — run on host; board smoke below) ---
# On host:
cargo test --package sgx-guardian-client circle::invite
# Expect: expired_token_rejected, tampered_byte_rejected, replayed_max_uses_rejected,
#         non_owner_mint_rejected, permission_escalation_blocked  — all pass

# Board smoke: tamper one char of the token → redeem must fail:
BAD=$(printf '%s' "$TOKEN" | sed 's/.$/X/')
curl -s -o /dev/null -w '%{http_code}\n' -X POST "$API/circles/redeem" -H 'content-type: application/json' \
  -d "{\"token_b64\":\"$BAD\",\"joiner_did\":\"$DUMMY_DID\"}"   # expect 4xx (signature invalid)
```

**Expected:**
```
Mint → {invite_id, token_b64, qr_payload, link, expires_at} returned
Unit: expired / tampered / replayed / non-owner-minted / permission-escalation ALL rejected
Board: tampered token → redeem rejected (4xx), audit "invite ... signature invalid"
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

---

## ⏳ Requirement 6 — [ ] QR-based invitations (QR payload + share link)

> Mint response mein `qr_payload` + `link` hone chahiye jo FE seedha scannable QR render kar sake — bina extra encoding. Compact encoding QR size budget ke andar.

**Commands (nodeA / owner):**
```bash
MINT=$(curl -s -X POST "$API/circles/$CID/invites" -H 'content-type: application/json' -d '{"role":"Member"}')
echo "$MINT" | python3 -c "import sys,json;d=json.load(sys.stdin);print('has qr_payload:', 'qr_payload' in d);print('has link:', 'link' in d);print('qr len:', len(d.get('qr_payload','')));print('link:', d.get('link'))"

# List minted invites for the circle:
curl -s "$API/circles/$CID/invites" | python3 -c "import sys,json;[print(i['invite_id'], i.get('expires_at')) for i in json.load(sys.stdin)]"

# Revoke an invite:
INV=$(echo "$MINT" | python3 -c "import sys,json;print(json.load(sys.stdin)['invite_id'])")
curl -s -o /dev/null -w '%{http_code}\n' -X DELETE "$API/circles/$CID/invites/$INV"   # expect 200
```

**Expected:**
```
Mint response has qr_payload + link; qr_payload within QR size budget (scannable as-is)
GET invites lists minted invites; DELETE revokes an invite (200)
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

---

## ⏳ Requirement 7 — [ ] Join flow end-to-end (2-node) + revoked-joiner rejected

> **Mutual-proof** flow: nodeA mints invite → nodeB `POST /circles/join` → nodeB builds signed JoinRequest → owner `redeem` runs the **6-step verification chain** → issues VC → nodeB holds a valid comms-circle VC. **Revoked joiner rejected** (`crl::is_revoked` gate). **This is "using DID/VC identity verification" end-to-end.**

**Commands (2-node — owner nodeA, joiner nodeB):**
```bash
# ⚠️ confirm reachability first:
nft list ruleset | grep 8443    # must be non-empty

# 1) Owner mints:
TOKEN=$(curl -s -X POST "$API/circles/$CID/invites" -H 'content-type: application/json' -d '{"role":"Member"}' \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['token_b64'])")

# 2) Joiner (nodeB) redeems via join:
ssh root@192.168.50.248 "curl -s -X POST http://localhost:8443/api/v1/circles/join -H 'content-type: application/json' -d '{\"token_b64\":\"$TOKEN\",\"owner_host\":\"$OWNER_HOST\"}'" | python3 -m json.tool

# 3) Joiner now holds a comms-circle VC:
ssh root@192.168.50.248 "curl -s http://localhost:8443/api/v1/vc/own" | python3 -c "import sys,json;[print(v['credentialSubject']['circleId']) for v in json.load(sys.stdin)]"

# 4) Owner's replay ledger shows one use:
python3 -c "import json,glob;[print(open(f).read()) for f in glob.glob('$CIRCLE_DIR/invites/redeemed.json')]"

# 5) Revoked joiner rejected — revoke a DUMMY member then try to redeem with it (dummy only!):
#    (use a fresh single-use invite + DUMMY_DID that is CRL-revoked in a dummy scenario)
```

**Expected:**
```
join → 201 { vc } ; nodeB /vc/own now includes circle-<uuid> (the comms circle)
redeemed.json shows invite_id with one redeemer (max_uses honoured)
A CRL-revoked joiner DID → redeem REJECTED (is_revoked gate, step 5 of the chain)
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

---

## ⏳ Requirement 8 — [ ] Remove from Circle = status-list revoke ONLY (CRL untouched)

> **Critical security correctness.** "Remove from Circle" comms-circle VC ko **status-list se revoke** karta hai — **CRL revoke NAHI** (warna device poore mesh se nikal jata). `crl/list` count remove se pehle aur baad **same** rehna chahiye.

**Commands (nodeA / owner):**
```bash
# CRL count BEFORE:
BEFORE=$(curl -s "$API/crl/list" | python3 -c "import sys,json;print(json.load(sys.stdin)['count'])")

# Remove the dummy member:
curl -s -o /dev/null -w '%{http_code}\n' -X DELETE "$API/circles/$CID/members/$DUMMY_DID"

# Member now Revoked in the comms circle (status-list), verify via VC status:
curl -s "$API/circles/$CID/members" | python3 -c "import sys,json;[print(m['did'][:20],m.get('state')) for m in json.load(sys.stdin)]"

# CRL count AFTER — MUST equal BEFORE:
AFTER=$(curl -s "$API/crl/list" | python3 -c "import sys,json;print(json.load(sys.stdin)['count'])")
echo "crl BEFORE=$BEFORE  AFTER=$AFTER  (must be equal)"
```

**Expected:**
```
DELETE member → comms-circle VC status-list bit set (member state=Revoked in this circle)
crl/list count UNCHANGED (BEFORE == AFTER) — remove did NOT fire a CRL/mesh revocation
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

---

## ⏳ Requirement 9 — [ ] Mesh Circle isolation + Milestone-4 guard (gossip/CRL unharmed)

> Mesh Circle **archive nahi ho sakta** (409). Comms-circle membership gossip ki circle-match check mein **leak nahi** hona chahiye (`current_circle_id()` → `load_own_any()` must return the **Mesh** VC). Gossip/CRL/attestation is feature se bilkul unaffected.

**Commands (nodeA):**
```bash
# Mesh Circle cannot be archived:
MESH=$(curl -s "$API/circles" | python3 -c "import sys,json;print([c['circle_id'] for c in json.load(sys.stdin) if c['kind']=='Mesh'][0])")
curl -s -o /dev/null -w '%{http_code}\n' -X POST "$API/circles/$MESH/archive"   # expect 409 Conflict

# current_circle_id must still resolve to the MESH circle (not a comms one):
curl -s "$API/vid/show" | python3 -c "import sys,json;print('runtime circle:', json.load(sys.stdin).get('circle_id','?'))" 2>/dev/null || \
  grep -a "current_circle_id\|circle=guardian-circle-alpha" /var/log/sgx-guardian/audit-nodeA.log | tail -2

# Milestone-4 guard — gossip + CRL healthy and unchanged:
curl -s "$API/crl/gossip/status" | python3 -c "import sys,json;d=json.load(sys.stdin);print('merkle_root:',d.get('merkle_root'));print('rounds_initiated:',d.get('rounds_initiated'))"
curl -s -X POST "$API/crl/gossip/trigger" | python3 -m json.tool
```

**Expected:**
```
Archive Mesh Circle → 409 Conflict (Mesh is read-only)
Runtime circle_id resolves to guardian-circle-alpha (Mesh) — comms VCs do NOT leak into gossip
crl/gossip/status healthy, rounds still initiating; gossip trigger works — Milestone 4 intact
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

---

# 🔌 API Verification — New Endpoints

## ⏳ API 1 — [ ] Circle CRUD

**Command:**
```bash
curl -s "$API/circles" | python3 -m json.tool                                             # list
curl -s -X POST "$API/circles" -H 'content-type: application/json' -d '{"name":"APItest"}' # create
curl -s "$API/circles/$CID" | python3 -m json.tool                                        # detail
curl -s -X PATCH "$API/circles/$CID" -H 'content-type: application/json' -d '{"name":"x"}' # edit
curl -s -o /dev/null -w '%{http_code}\n' -X POST "$API/circles/$CID/archive"              # archive
```

**Expected:**
```
GET list → Mesh + comms circles ; POST → 201 ; GET detail → circle ;
PATCH → renamed ; POST archive → 200 (comms) / 409 (mesh)
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

## ⏳ API 2 — [ ] Members

**Command:**
```bash
curl -s -X POST "$API/circles/$CID/members" -H 'content-type: application/json' -d "{\"did\":\"$DUMMY_DID\",\"role\":\"Member\"}" | python3 -m json.tool
curl -s "$API/circles/$CID/members" | python3 -m json.tool
curl -s -X PATCH "$API/circles/$CID/members/$DUMMY_DID" -H 'content-type: application/json' -d '{"role":"Owner"}' | python3 -m json.tool
curl -s -o /dev/null -w '%{http_code}\n' -X DELETE "$API/circles/$CID/members/$DUMMY_DID"
```

**Expected:**
```
POST → VC issued ; GET → members with role+state ; PATCH → role changed ; DELETE → 200 (status-list revoke)
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

## ⏳ API 3 — [ ] Invites

**Command:**
```bash
curl -s -X POST "$API/circles/$CID/invites" -H 'content-type: application/json' -d '{"role":"Member"}' | python3 -m json.tool
curl -s "$API/circles/$CID/invites" | python3 -m json.tool
curl -s -o /dev/null -w '%{http_code}\n' -X DELETE "$API/circles/$CID/invites/<invite_id>"
```

**Expected:**
```
POST → {invite_id, token_b64, qr_payload, link, expires_at} ; GET → minted list ; DELETE → 200
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

## ⏳ API 4 — [ ] Join / Redeem

**Command:**
```bash
# Preview (joiner decodes + previews before accepting):
ssh root@192.168.50.248 "curl -s -X POST http://localhost:8443/api/v1/circles/join/preview -H 'content-type: application/json' -d '{\"token_b64\":\"$TOKEN\"}'" | python3 -m json.tool
# Join (joiner) → owner redeem (server-to-server) → VC:
ssh root@192.168.50.248 "curl -s -X POST http://localhost:8443/api/v1/circles/join -H 'content-type: application/json' -d '{\"token_b64\":\"$TOKEN\",\"owner_host\":\"$OWNER_HOST\"}'" | python3 -m json.tool
```

**Expected:**
```
join/preview → circle_name + role shown (no state change)
join → 201 { vc } ; owner /circles/redeem ran the 6-step chain ; joiner saved the VC
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

## ⏳ API 5 — [ ] Security — non-owner authorization + tampered registry rejected

**Command:**
```bash
# Non-owner mutation → 403:
ssh root@192.168.50.248 "curl -s -o /dev/null -w '%{http_code}\n' -X POST http://$OWNER_HOST:8443/api/v1/circles -H 'content-type: application/json' -d '{\"name\":\"hacktest\"}'"

# Tampered registry → rejected on read (flip a byte, then restart):
cp "$CIRCLE_DIR/circles.json" /tmp/circles.bak
python3 -c "import json;r=json.load(open('$CIRCLE_DIR/circles.json'));r['circles'][-1]['name']='TAMPERED';json.dump(r,open('$CIRCLE_DIR/circles.json','w'))"
pkill -f sgx_guardian_client && sleep 3 && ./sgx_guardian_client nodeA & sleep 8
grep -a "circles.*invalid\|registry.*signature\|circle registry rejected" /var/log/sgx-guardian/audit-nodeA.log | tail -2
# RESTORE:
cp /tmp/circles.bak "$CIRCLE_DIR/circles.json" && pkill -f sgx_guardian_client && sleep 3 && ./sgx_guardian_client nodeA &
```

**Expected:**
```
Non-owner POST → 403 (ensure_circle_owner)
Tampered circles.json → signature rejected on load (fail-closed), audit line present
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

---

## 🗺️ Test-Tag Mapping (CIRCLE-series)

| Tag | What it proves | Section above |
|---|---|---|
| CIRCLE-001 | Circle creation + Mesh Circle seeded | Req 1 |
| CIRCLE-002 | Circle editing (rename, persisted) | Req 2 |
| CIRCLE-003 | Membership management (add + list via VC) | Req 3 |
| CIRCLE-004 | Member admin + DID/VC authorization (non-owner 403) | Req 4 |
| CIRCLE-005 | Signed invite tokens (expired/tampered/replayed/non-owner rejected) | Req 5 |
| CIRCLE-006 | QR-based invitations (qr_payload + link) | Req 6 |
| CIRCLE-007 | Join flow end-to-end (2-node) + revoked-joiner rejected | Req 7 |
| CIRCLE-008 | Remove = status-list revoke ONLY (CRL untouched) | Req 8 |
| CIRCLE-009 | Mesh Circle isolation + Milestone-4 guard | Req 9 |

---

## ⚙️ Known Issue Placeholders (fill during testing)

### Issue 1 — ____
```
(symptoms / root cause / fix)
```

---

## 🧰 Emergency & Debug Commands

```bash
API=http://localhost:8443/api/v1
CIRCLE_DIR=/var/lib/sgx-guardian/identity/circles

# ⚠️ Join-flow reachability (the silent-failure check):
nft list ruleset | grep 8443

# API reachable on both nodes?
curl -s "$API/health" | python3 -m json.tool

# Registry + invites on disk:
cat "$CIRCLE_DIR/circles.json" | python3 -m json.tool
ls -l "$CIRCLE_DIR/invites/" ; cat "$CIRCLE_DIR/invites/redeemed.json" 2>/dev/null

# Full circle trail:
grep -a "Circle\|invite\|member" /var/log/sgx-guardian/audit-nodeA.log | tail -20

# Milestone-4 guard — CRL/gossip untouched:
curl -s "$API/crl/list" | python3 -c "import sys,json;print('crl count:',json.load(sys.stdin)['count'])"
curl -s "$API/crl/gossip/status" | python3 -c "import sys,json;print(json.load(sys.stdin).get('merkle_root'))"

# Which circle does the runtime resolve to? (must be the MESH one)
curl -s "$API/vc/own" | python3 -c "import sys,json;[print(v['credentialSubject']['circleId']) for v in json.load(sys.stdin)]"

# Reset circle test state (dummy circles only):
pkill -f sgx_guardian_client
rm -rf "$CIRCLE_DIR"        # re-seeds Mesh Circle from owner VC on next boot
./sgx_guardian_client nodeA

# Isolate a clean test run (empty circle dir override):
SGX_GUARDIAN_CIRCLE_BASE=/tmp/circle-test ./sgx_guardian_client nodeA
```

**Timing cheat-sheet:** Circle CRUD/members/invites are synchronous REST → immediate · join flow does one server-to-server HTTP hop (owner redeem) — allow a couple of seconds · invite default expiry is 24h (clamp 5min..30d) · registry seeds lazily on the first `GET /circles`.

---

## 🔗 Cross-feature note

Ye feature **VC layer (already live)** ke upar baithi hai — "add member" ki poori implementation `issue_membership_vc(circle_id = comms circle)` hai. Naya sirf: Circle **entity/registry**, CRUD, **invite tokens + QR**, aur **join/redeem** flow. **Mesh Circle read-only hai** aur **CRL gossip bilkul untouched** — yehi is design ka pura point hai (Milestone-4 risk zero). Chat / Calls / Files features baad mein **comms `circle_id`** ko membership scope ke taur par use karengi.
