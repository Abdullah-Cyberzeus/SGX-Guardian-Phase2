# Notification Preferences + Push — Verification Log
**Board:** nodeA (192.168.50.115) — iMX8MP (ARM64)  ·  *(optional independence check: nodeB 192.168.50.248)* | **Date:** ______ | **Tester:** Asad Ali
**Test tag:** NOTIF-series (NOTIF-001 – NOTIF-009) | **Plan:** `Notification_Preferences_Push_Complete_Plan.md`

---

## 📌 Task Description

> Implement notification preference management, delivery pipelines, push services, severity filtering, and real-time notification subscriptions. Preferences cover three categories — **Alerts** (high/medium/low severity), **Devices** (new device discovered, device pending approval, Guardian offline), and **Circles** (new messages, incoming calls, member joined). Live delivery is over **SSE** with `Last-Event-ID` replay; notifications are **persisted** so nothing is lost when no console is connected. Channel decision: **SSE** (offline/LAN, rides the existing admin API, no cloud) — not FCM/APNs. Circle sources are **defined-but-unfired** seams until File Transfer / Chat / Calls / Circle features land.

---

## 📋 How to Use This File

**Jab bhi koi Requirement ya API verify ho jaye (PASS):**
1. `[ ]` ko `[x]` karo aur `## ⏳` ko `## ✅` kar do
2. **Commands:** section mein woh exact command likhna jo run kiya
3. **Result:** section mein terminal output paste karna
4. **Verdict:** ek line mein confirm karna — kya pass hua

**Jab koi Requirement ya API FAIL ho:**
1. **Pehle command side verify karo** — command galat bhi ho sakti hai, code galat nahi bhi ho sakta:
   - Kya daemon chal raha hai (`pgrep -f sgx_guardian_client`)?
   - Kya admin API up hai (`curl -s http://localhost:8443/api/v1/health`)?
   - Kya notification persistence task start hui (`grep -a "Notification persistence" /var/log/sgx-guardian/audit-nodeA.log`)?
   - SSE test ke liye — kya `curl -N` connection **open** rehti hai (streaming; -N = no-buffer, warna frames dikhenge nahi)?
   - Alerts source test (NOTIF-006) ke liye — kya threat/Suricata engine chal raha hai? Warna koi alert generate hi nahi hoga
   - Filtering test ke liye — kya pref actually persist hui (`PUT` ke baad `GET /notifications/prefs` se confirm)?
   - Alternate command / dobara try karo
2. **Sirf tab `❌` lagao** jab fully confirm ho jaye ke issue code side ka hai, command side ka nahi
3. **`❌` lagane ke saath ye bhi likho:**
   - Konsi file/function mein likely issue hai (e.g. `src/notify/bus.rs::publish`, `src/notify/prefs.rs::filter`, `src/notify/store.rs`, `src/api/handlers/notify.rs::stream`) (cross-check khud bhi karo — issue doosri file mein bhi ho sakta hai)
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
# Board pe — old process band, naya binary deploy, phir start:
pkill -f sgx_guardian_client || true
# (scp new binary here)
export SGX_NOTIFY_MAX_EVENTS=2000            # store ring cap (plan default 2000)
./sgx_guardian_client nodeA

# Handy variables:
API=http://localhost:8443/api/v1
SELF_DID=$(jq -r .did /var/lib/sgx-guardian/identity/did.json)
NOTIFY_DIR=/var/lib/sgx-guardian/notify       # events.jsonl + prefs.json

# Confirm persistence task started + store dir exists:
grep -a "Notification persistence" /var/log/sgx-guardian/audit-nodeA.log | tail -1
ls -l "$NOTIFY_DIR"

# --- Test alert injector (for NOTIF-006) ---
# Suricata alert ko notification banne ke liye ek EVE alert line inject karte hain jo
# tailer read karke forward_to_ai + publish_alert tak pohchati hai.
# (EVE path apni Suricata config se confirm karo — default niche.)
EVE_LOG=/opt/suricata/var/log/eve.json
inject_alert () {  # usage: inject_alert <severity 1|2|3> <signature>
  printf '{"timestamp":"%s","event_type":"alert","src_ip":"10.0.0.9","dest_ip":"10.0.0.1","proto":"TCP","alert":{"severity":%s,"signature":"%s","category":"Test","signature_id":9990001}}\n' \
    "$(date -u +%FT%T.000000+0000)" "$1" "$2" >> "$EVE_LOG"
}
```

> **Note:** Ye feature **per-Guardian local** hai — notifications us console tak jate hain jo isi Guardian se connected hai. CRL gossip ki tarah cross-node propagation **nahi** hai (by design). Isliye zyada-tar requirements **nodeA single-node** pe run hoti hain. Optional independence check: nodeB apni alag store rakhta hai — nodeA ke notifications nodeB pe show nahi hone chahiye.

---

## ⏳ Requirement 1 — [ ] Delivery pipeline — notification bus, non-blocking publish

> Ek in-process broadcast bus hai (`OnceLock<broadcast::Sender>`, clone of `ai_bridge.rs`) jispe koi bhi feature `publish()` karti hai. `publish()` non-blocking hai (no subscriber ho to no-op) — eve-loop ko block nahi karti. Persistence task bus se subscribe karke events store karti hai.

**Commands (nodeA):**
```bash
# Persistence task bus se subscribe karti hai — startup line confirm:
grep -a "Notification persistence" /var/log/sgx-guardian/audit-nodeA.log | tail -1
# Ek event inject karke dekho pipeline flow karti hai (store mein aata hai):
inject_alert 1 "NOTIF-001 pipeline probe"
sleep 2
curl -s "$API/notifications" | python3 -m json.tool | head -20
# Daemon still responsive (publish non-blocking):
curl -s "$API/health" | python3 -m json.tool
```

**Expected:**
```
audit: Notification persistence started store=/var/lib/sgx-guardian/notify max_events=2000
GET /notifications → injected event present (title/severity populated)
API keeps answering — publish is in-memory + non-blocking, no board freeze
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

---

## ⏳ Requirement 2 — [ ] Notification preference management (persisted + signed)

> Teen categories ke toggles (Alerts/Devices/Circles) — GET/PUT se manage hote hain, signed `prefs.json` mein persist hote hain, aur restart ke baad survive karte hain. Default sab ON. Tampered prefs reject hone chahiye (API 5).

**Commands (nodeA):**
```bash
# Current prefs (fresh: all-on defaults):
curl -s "$API/notifications/prefs" | python3 -m json.tool

# Change a toggle + persist:
curl -s -X PUT "$API/notifications/prefs" -H "Content-Type: application/json" \
  -d '{"alerts":{"high":true,"medium":false,"low":false}}' | python3 -m json.tool

# On disk — signed + updated:
python3 -c "import json;p=json.load(open('$NOTIFY_DIR/prefs.json'));print('alerts:',p['alerts']);print('has_proof:', 'proof' in p);print('sequence:',p.get('sequence'))"

# Restart → prefs persist:
pkill -f sgx_guardian_client && sleep 3 && ./sgx_guardian_client nodeA &
sleep 8
curl -s "$API/notifications/prefs" | python3 -m json.tool | grep -A3 '"alerts"'
```

**Expected:**
```
Default GET: alerts{high,medium,low all true}, devices{...true}, circles{...true}
After PUT: alerts.medium=false, alerts.low=false persisted, sequence incremented, re-signed
prefs.json: signed (proof present), values match
After restart: medium=false still — persisted across daemon restart
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

---

## ⏳ Requirement 3 — [ ] Real-time subscription over SSE (push services)

> Console `GET /notifications/stream` pe subscribe karta hai; ek naya event live SSE `data:` line ke through aa jata hai — bina poll kiye. Keep-alive heartbeat connection ko open rakhta hai.

**Commands (nodeA — 2 terminals):**
```bash
# Terminal 1 — open the stream (streaming, keep open; -N = no buffering):
curl -N "$API/notifications/stream"

# Terminal 2 — trigger an event:
inject_alert 1 "NOTIF-003 live push"

# Back in Terminal 1: a new SSE frame should appear within ~1-2s:
#   id: <n>
#   data: {"kind":"AlertHigh","title":"...","severity":"high",...}
```

**Expected:**
```
Terminal 1 stays connected (keep-alive heartbeat holds it open)
On inject → an SSE frame arrives live: "id: <n>" + "data: {…AlertHigh…}"
No polling, no page refresh — server-pushed
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

---

## ⏳ Requirement 4 — [ ] Severity / category filtering

> Event tabhi deliver hota hai jab uska matching preference toggle ON ho (`filter(kind) -> bool`). Off toggle ka event **stream pe nahi aana chahiye**.

**Commands (nodeA — 2 terminals):**
```bash
# Set: High ON, Medium OFF:
curl -s -X PUT "$API/notifications/prefs" -H "Content-Type: application/json" \
  -d '{"alerts":{"high":true,"medium":false,"low":false}}' >/dev/null

# Terminal 1 — open stream:
curl -N "$API/notifications/stream"

# Terminal 2 — inject a MEDIUM (severity 2) then a HIGH (severity 1):
inject_alert 2 "NOTIF-004 medium (should be filtered)"
sleep 2
inject_alert 1 "NOTIF-004 high (should pass)"
```

**Expected:**
```
MEDIUM alert → does NOT appear on the stream (alerts.medium=false)
HIGH  alert → appears on the stream (alerts.high=true)
Filtering is preference-driven, kind → toggle mapping correct
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

---

## ⏳ Requirement 5 — [ ] Durability + `Last-Event-ID` replay + restart persistence

> (a) Koi console connected na ho tab bhi event **store mein persist** hota hai (lost nahi hota). (b) Reconnect pe `Last-Event-ID` se missed events **replay** hote hain, phir live. (c) Notifications daemon restart ke baad bhi rehte hain (capped ring + atomic JSONL).

**Commands (nodeA):**
```bash
# (a) No client connected — inject 2 events:
inject_alert 1 "NOTIF-005 offline-1"
inject_alert 1 "NOTIF-005 offline-2"
sleep 2
curl -s "$API/notifications" | python3 -c "import sys,json;d=json.load(sys.stdin);print('count:',len(d));[print(e['id'],e['title']) for e in d[-3:]]"
# note an OLDER id as LAST_ID for the replay test

# (b) Reconnect with Last-Event-ID → only NEWER events replay first, then live:
LAST_ID=<put an older id here>
curl -N -H "Last-Event-ID: $LAST_ID" "$API/notifications/stream"

# (c) Persistence across restart:
pkill -f sgx_guardian_client && sleep 3 && ./sgx_guardian_client nodeA &
sleep 8
curl -s "$API/notifications" | python3 -c "import sys,json;print('count after restart:',len(json.load(sys.stdin)))"
```

**Expected:**
```
(a) Both offline events present in /notifications despite no console connected — nothing lost
(b) Stream opened with Last-Event-ID replays ONLY events with id > LAST_ID, then switches to live
(c) count after restart is non-zero — events.jsonl survived (atomic write, capped ring)
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

---

## ⏳ Requirement 6 — [ ] Alerts source wired (Suricata → notification)

> Ek real Suricata alert (High/Medium/Low) ke saath `publish_alert` fire hota hai (`forward_to_ai` ke bilkul saath) — matlab Alerts category ka concrete source live hai. `publish_alert` severity map karta hai: sev 1→AlertHigh, 2→AlertMedium, 3→AlertLow.

**Commands (nodeA):**
```bash
# Prefs sab ON kar do taake filter interfere na kare:
curl -s -X PUT "$API/notifications/prefs" -H "Content-Type: application/json" \
  -d '{"alerts":{"high":true,"medium":true,"low":true}}' >/dev/null

# Option A — real Suricata rule trigger karo (e.g. known ICMP test-rule)
# Option B — deterministic: EVE line inject karo:
inject_alert 1 "NOTIF-006 suricata-high"
sleep 3

# Confirm: notification store + audit dono mein aaya:
curl -s "$API/notifications" | python3 -c "import sys,json;[print(e['kind'],e['title']) for e in json.load(sys.stdin)[-3:]]"
grep -a "Notify\|notification raised\|publish_alert" /var/log/sgx-guardian/audit-nodeA.log | tail -3
```

**Expected:**
```
Suricata High alert → NotificationKind::AlertHigh in the store, title carries the signature
severity mapping: sev 1→AlertHigh, 2→AlertMedium, 3→AlertLow
audit: notification raised (category=Notify)  — wired next to forward_to_ai
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

---

## ⏳ Requirement 7 — [ ] Decoupled future seams (Circle events defined-but-unfired)

> Circle/transfer/chat/call notification kinds **model mein defined** hain (`CircleNewMessage`, `CircleIncomingCall`, `CircleMemberJoined`, `CircleFileShared`) lekin abhi **koi source fire nahi karta** (woh features build nahi hue). Coupling nahi honi chahiye — module in features ke baghair build/run karta hai.

**Commands (nodeA + host):**
```bash
# Circle toggles present + persist ho rahe hain:
curl -s "$API/notifications/prefs" | python3 -c "import sys,json;p=json.load(sys.stdin);print('circles keys:',list(p['circles'].keys()))"

# Abhi tak koi Circle-kind event store mein NAHI hona chahiye:
curl -s "$API/notifications" | python3 -c "import sys,json;d=json.load(sys.stdin);ck=[e for e in d if str(e['kind']).startswith('Circle')];print('circle-kind events so far:',len(ck))"

# Build sanity (host): notify module bina un features ke compile hota hai
grep -rn "CircleNewMessage\|CircleIncomingCall\|CircleMemberJoined\|CircleFileShared" src/notify/model.rs | head
```

**Expected:**
```
circles keys: [new_message, incoming_call, member_joined]  (toggles exist + persist)
circle-kind events so far: 0  (variants defined, nothing fires them yet — no coupling)
Enum variants present in src/notify/model.rs; module builds standalone
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

---

# 🔌 API Verification — New Endpoints

## ⏳ API 1 — [ ] GET `/api/v1/notifications/stream` (SSE)

**Command:**
```bash
curl -N -m 10 "$API/notifications/stream"   # -m 10: auto-close after 10s for a bounded test
```

**Expected:**
```
Content-Type: text/event-stream
Keep-alive comments (":" heartbeats) hold the connection
On any published+allowed event: "id: <n>\n" then "data: {json}\n\n"
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

## ⏳ API 2 — [ ] GET + PUT `/api/v1/notifications/prefs`

**Command:**
```bash
curl -s "$API/notifications/prefs" | python3 -m json.tool
curl -s -X PUT "$API/notifications/prefs" -H "Content-Type: application/json" \
  -d '{"devices":{"new_device":true,"pending_approval":true,"guardian_offline":false}}' | python3 -m json.tool
```

**Expected:**
```json
{
  "alerts":  {"high": true, "medium": true, "low": true},
  "devices": {"new_device": true, "pending_approval": true, "guardian_offline": true},
  "circles": {"new_message": true, "incoming_call": true, "member_joined": true},
  "sequence": 0
}
```
**Note:** PUT ke baad `sequence` increment + `prefs.json` re-signed hona chahiye.

**Result:**
```
(paste output)
```

**Verdict:** ⏳

## ⏳ API 3 — [ ] GET `/api/v1/notifications` (history) + `/unread-count`

**Command:**
```bash
curl -s "$API/notifications" | python3 -c "import sys,json;d=json.load(sys.stdin);print('total:',len(d))"
curl -s "$API/notifications/unread-count" | python3 -m json.tool
```

**Expected:**
```
total: <n>   (capped at SGX_NOTIFY_MAX_EVENTS = 2000)
{"unread": <k>}   (k = events with read=false)
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

## ⏳ API 4 — [ ] POST `/api/v1/notifications/:id/read` + `/read-all`

**Command:**
```bash
# Pick one id from history:
ID=$(curl -s "$API/notifications" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d[-1]['id'] if d else '')")
curl -s -X POST "$API/notifications/$ID/read" | python3 -m json.tool
curl -s "$API/notifications/unread-count" | python3 -m json.tool   # should drop by 1

curl -s -X POST "$API/notifications/read-all" | python3 -m json.tool
curl -s "$API/notifications/unread-count" | python3 -m json.tool   # should be 0
```

**Expected:**
```
After :id/read → that event read=true, unread-count drops by 1
After read-all → unread=0
Changes persist in events.jsonl (survive restart)
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

## ⏳ API 5 — [ ] Security — tampered `prefs.json` rejected (signature re-verification)

> `prefs.json` ki ek value ko manually flip karke daemon restart karte hain — signed prefs invalid ho jaani chahiye, tampered value honor NA ho (fail-closed → safe defaults ya last-good reject).

**Command (nodeA):**
```bash
# Backup + tamper (flip a toggle without re-signing):
cp "$NOTIFY_DIR/prefs.json" /tmp/prefs.bak
python3 -c "import json;p=json.load(open('$NOTIFY_DIR/prefs.json'));p['alerts']['high']=False;json.dump(p,open('$NOTIFY_DIR/prefs.json','w'))"
pkill -f sgx_guardian_client && sleep 3 && ./sgx_guardian_client nodeA &
sleep 8

# Audit should show signature rejection; tampered value must NOT silently take effect:
grep -a "prefs.*invalid\|prefs.*signature\|notification prefs rejected" /var/log/sgx-guardian/audit-nodeA.log | tail -2
curl -s "$API/notifications/prefs" | python3 -m json.tool | grep -A3 '"alerts"'

# RESTORE:
cp /tmp/prefs.bak "$NOTIFY_DIR/prefs.json"
pkill -f sgx_guardian_client && sleep 3 && ./sgx_guardian_client nodeA &
```

**Expected:**
```
audit: notification prefs signature invalid → fail-closed (defaults, or reject to last-good)
Tampered alerts.high=false is NOT honored — no silent acceptance of unsigned edits
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

---

## 🗺️ Test-Tag Mapping (NOTIF-series)

| Tag | What it proves | Section above |
|---|---|---|
| NOTIF-001 | Bus + non-blocking publish (delivery pipeline) | Req 1 |
| NOTIF-002 | Preference management persisted + signed | Req 2 |
| NOTIF-003 | Real-time SSE subscription (push) | Req 3 |
| NOTIF-004 | Severity / category filtering | Req 4 |
| NOTIF-005 | Durability + `Last-Event-ID` replay + restart persistence | Req 5 |
| NOTIF-006 | Alerts source wired (Suricata → notification) | Req 6 |
| NOTIF-007 | Decoupled future seams (Circle kinds unfired) | Req 7 |
| NOTIF-008 | History / unread / mark-read APIs | API 3 + API 4 |
| NOTIF-009 | Signed-prefs tamper rejection (fail-closed) | API 5 |

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
NOTIFY_DIR=/var/lib/sgx-guardian/notify

# Persistence task alive? (startup line)
grep -a "Notification persistence" /var/log/sgx-guardian/audit-nodeA.log | tail -1

# API reachable?
curl -s "$API/health" | python3 -m json.tool

# Full notification trail on a node:
grep -a "Notify\|notification" /var/log/sgx-guardian/audit-nodeA.log | tail -20

# Store + prefs on disk:
wc -l "$NOTIFY_DIR/events.jsonl" 2>/dev/null ; cat "$NOTIFY_DIR/prefs.json" | python3 -m json.tool

# SSE quick smoke (auto-closes after 8s):
curl -N -m 8 "$API/notifications/stream"

# Confirm EVE tailer / threat engine running (needed for Alerts source, NOTIF-006):
pgrep -f suricata ; ls -l /opt/suricata/var/log/eve.json

# Threat pipeline unharmed (we wired NEXT TO, not INTO, forward_to_ai):
curl -s "$API/threat/alerts?limit=5" | python3 -c "import sys,json;print('threat alerts:',len(json.load(sys.stdin)))"

# Reset notification test state (history only; prefs preserved):
pkill -f sgx_guardian_client
rm -f "$NOTIFY_DIR/events.jsonl"
./sgx_guardian_client nodeA

# Isolate a clean test run (empty store dir override):
SGX_GUARDIAN_NOTIFY_BASE=/tmp/notify-test ./sgx_guardian_client nodeA
```

**Timing cheat-sheet:** SSE delivery is event-driven → a published+allowed event reaches an open stream in ~1-2 s · no interval to wait for (unlike gossip) · Alerts source depends on the Suricata/EVE pipeline being live · `curl -N` (no-buffer) is required to see streamed frames.

---

## 🔗 Cross-feature note

Notification ka **ekmatra live source** abhi threat pipeline hai (Suricata → `publish_alert` next to `forward_to_ai`). Device / Guardian-offline sources apne event sites pe wire hote hain (same one-line `notify::publish(...)`). **Circle sources (new message / incoming call / member joined / file shared) tab fire honge jab In-Circle File Transfer / Chat / Calls / Circle-container features land karenge** — woh features sirf `crate::notify::publish(NotificationEvent{ kind: … })` call karengi, is module mein koi change nahi. Seam already yahan mojood hai.
