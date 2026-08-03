# Notification Preferences + Push - Docker Verification Log
**Environment:** Docker container cohort (WSL2) | **Date:** 2026-07-20 | **Tester:** Asad Ali
**Test tag:** NOTIF-series (NOTIF-001 - NOTIF-009) | **Plan:** `docs/Notification_Preferences_Push_Complete_Plan.md`

---

## 📌 Task Description

> Implement notification preference management, delivery pipelines, push services, severity filtering, and real-time notification subscriptions. Preferences cover three categories - **Alerts** (high/medium/low severity), **Devices** (new device discovered, device pending approval, Guardian offline), and **Circles** (new messages, incoming calls, member joined). Live delivery is over **SSE** with `Last-Event-ID` replay; notifications are **persisted** so nothing is lost when no console is connected.

---

## 📋 Logging Rule For This File

- Is file mein **sirf confirmed PASS** steps record kiye ja rahe hain.
- Failed ya inconclusive commands yahan intentionally **record nahi** ki ja rahi.
- Jab koi nayi requirement pass ho, uska exact command, observed result, aur verdict yahin append/update hoga.

---

## ✅ Latest Verified Status

- Docker cohort stable hai:
  - `nodeA` -> `http://127.0.0.1:18443`
  - `nodeB` -> `http://127.0.0.1:28444`
  - `nodeC` -> `http://127.0.0.1:38443`
- `nodeA` notification store bootstrap ho chuka hai:
  - `/var/lib/sgx-guardian/notify/events.jsonl`
  - `/var/lib/sgx-guardian/notify/prefs.json`
- Confirmed pass count abhi:
  - Requirements: `7/7`
  - APIs: `5/5`
- SSE keep-alive aur live pushed `data:` frame dono verify ho chuke hain.

---

## 🐳 Docker Notes

- Saari commands **host WSL terminal** se chalani hain.
- `docker exec` bhi host shell se chalega; container ke andar ja kar `docker exec` mat chalana.
- Is current run mein `nodeB` host port `28444` use kar raha hai, kyun ke `28443` conflict kar raha tha.
- `nodeA` par threat config manually seed karni pari taa-ke alert-source verification chal sake.

---

## ⚡ Session Bootstrap Used In This Run

**Commands:**
```bash
cd /home/asad/SGX
sed -i 's/^NODEB_REST_PORT=.*/NODEB_REST_PORT=28444/' optional/container-cohort/dev.env
./optional/container-cohort/down.sh
./optional/container-cohort/up.sh
./optional/container-cohort/ps.sh

A=http://127.0.0.1:18443
B=http://127.0.0.1:28444
C=http://127.0.0.1:38443

docker exec sgx-nodeA sh -lc 'mkdir -p /etc/sgx-guardian/threat /var/log/suricata'
docker cp config/threat/config.yaml sgx-nodeA:/etc/sgx-guardian/threat/config.yaml
docker exec sgx-nodeA sh -lc "sed -i 's/^enabled: false/enabled: true/' /etc/sgx-guardian/threat/config.yaml"
docker exec sgx-nodeA sh -lc 'cat /etc/sgx-guardian/threat/config.yaml'
docker restart sgx-nodeA
until curl -sf "$A/api/v1/health" >/dev/null; do sleep 2; done

inject_alert () {
  docker exec -e SEV="$1" -e SIG="$2" sgx-nodeA sh -lc 'mkdir -p /var/log/suricata; touch /var/log/suricata/eve.json; printf "{\"timestamp\":\"%s\",\"event_type\":\"alert\",\"src_ip\":\"10.0.0.9\",\"dest_ip\":\"10.0.0.1\",\"proto\":\"TCP\",\"alert\":{\"severity\":%s,\"signature\":\"%s\",\"category\":\"Test\",\"signature_id\":9990001}}\n" "$(date -u +%FT%T.000000+0000)" "$SEV" "$SIG" >> /var/log/suricata/eve.json'
}
```

**Observed:**
```text
nodeA healthy
nodeB up on 28444
nodeC up on 38443
threat config present on nodeA with enabled: true
```

---

## 📊 Requirements Checklist

- [x] Requirement 1 - Delivery pipeline - notification bus, non-blocking publish
- [x] Requirement 2 - Notification preference management (persisted + signed)
- [x] Requirement 3 - Real-time subscription over SSE (push services)
- [x] Requirement 4 - Severity / category filtering
- [x] Requirement 5 - Durability + `Last-Event-ID` replay + restart persistence
- [x] Requirement 6 - Alerts source wired (Suricata -> notification)
- [x] Requirement 7 - Decoupled future Circle events

---

## 📊 API Checklist

- [x] API 1 - GET `/api/v1/notifications/stream`
- [x] API 2 - GET + PUT `/api/v1/notifications/prefs`
- [x] API 3 - GET `/api/v1/notifications` + `/unread-count`
- [x] API 4 - POST `/api/v1/notifications/:id/read` + `/read-all`
- [x] API 5 - Security - tampered `prefs.json` rejected

---

## ✅ Requirement 1 - Delivery pipeline - notification bus, non-blocking publish

**Commands:**
```bash
inject_alert 1 "NOTIF-001 pipeline probe"
sleep 3
curl -s "$A/api/v1/notifications?limit=5" | python3 -m json.tool
docker exec sgx-nodeA sh -lc 'tail -n 5 /var/lib/sgx-guardian/notify/events.jsonl'
curl -s "$A/api/v1/health"
```

**Expected:**
```text
Injected event notifications history mein appear ho
events.jsonl mein persisted row likhi jaye
API responsive rahe - publish path non-blocking ho
```

**Result:**
```text
GET /notifications returned:
- id: "1"
- kind: "alert_high"
- title: "Threat alert on nodeA"
- body: "NOTIF-001 pipeline probe from 10.0.0.9:0 to 10.0.0.1:0 (other)"

events.jsonl tail contained the same event as a persisted JSON line
/api/v1/health returned: ok
```

**Verdict:** PASS - notification pipeline ne alert ko ingest, persist, aur history API se serve kiya; daemon responsive raha.

---

## ✅ Requirement 2 - Notification preference management (persisted + signed)

**Commands:**
```bash
curl -s "$A/api/v1/notifications/prefs" | python3 -m json.tool

curl -s -X PUT "$A/api/v1/notifications/prefs" \
  -H "Content-Type: application/json" \
  -d '{"alerts":{"high":true,"medium":false,"low":false}}' | python3 -m json.tool

docker exec sgx-nodeA sh -lc 'cat /var/lib/sgx-guardian/notify/prefs.json' | python3 -m json.tool

docker restart sgx-nodeA
until curl -sf "$A/api/v1/health" >/dev/null; do sleep 2; done
curl -s "$A/api/v1/notifications/prefs" | python3 -m json.tool
```

**Expected:**
```text
Default prefs all-on milen
PUT ke baad medium=false aur low=false persist hon
sequence increment ho
proof re-signed ho
restart ke baad values survive karein
```

**Result:**
```text
Initial GET returned alerts.high=true, alerts.medium=true, alerts.low=true
PUT returned alerts.high=true, alerts.medium=false, alerts.low=false
sequence moved from 1 -> 2
prefs.json on disk contained the updated values plus proof
restart ke baad GET still returned medium=false and low=false
```

**Verdict:** PASS - prefs API, persistence, signature material, aur restart survival verify ho gaye.

---

## ✅ Requirement 3 - Real-time subscription over SSE (push services)

**Commands:**
```bash
# Terminal 2 - stream open rakha gaya:
cd /home/asad/SGX
A=http://127.0.0.1:18443
curl -N "$A/api/v1/notifications/stream"
```

```bash
# Terminal 1 - unique alert publish kiya gaya:
cd /home/asad/SGX
A=http://127.0.0.1:18443

inject_alert_unique () {
  docker exec -e SEV="$1" -e SIG="$2" sgx-nodeA sh -lc 'mkdir -p /var/log/suricata; touch /var/log/suricata/eve.json; SID=$(date +%s); printf "{\"timestamp\":\"%s\",\"event_type\":\"alert\",\"src_ip\":\"10.0.0.9\",\"dest_ip\":\"10.0.0.1\",\"proto\":\"TCP\",\"alert\":{\"severity\":%s,\"signature\":\"%s\",\"category\":\"Test\",\"signature_id\":%s}}\n" "$(date -u +%FT%T.000000+0000)" "$SEV" "$SIG" "$SID" >> /var/log/suricata/eve.json'
}

inject_alert_unique 1 "NOTIF-003 live push unique"
sleep 3

curl -s "$A/api/v1/notifications?limit=5" | python3 -m json.tool
docker exec sgx-nodeA sh -lc 'tail -n 5 /var/lib/sgx-guardian/notify/events.jsonl'
```

**Expected:**
```text
Terminal 2 par SSE stream open rahe
Heartbeat ":" frames aate rahen
Inject ke baad actual SSE event frame aaye:
event: notification
id: <n>
data: {"kind":"alert_high",...}
History aur events.jsonl mein same event persist ho
```

**Result:**
```text
Terminal 1 history returned:
- id: "2"
- kind: "alert_high"
- title: "Threat alert on nodeA"
- body: "NOTIF-003 live push unique from 10.0.0.9:0 to 10.0.0.1:0 (other)"
- severity: "high"
- read: false

events.jsonl contained id=1 and id=2 persisted events.

Terminal 2 SSE output:
event: notification
id: 2
data: {"id":"2","kind":"alert_high","title":"Threat alert on nodeA","body":"NOTIF-003 live push unique from 10.0.0.9:0 to 10.0.0.1:0 (other)","severity":"high","ref_id":"1629338319b58038","created_at":"2026-07-20T10:12:18.431732584+00:00","read":false}

Heartbeat ":" frames continued after the event.
```

**Verdict:** PASS - SSE stream ne live notification event push kiya without polling, aur connection keep-alive heartbeats ke saath open rahi.

---

## ✅ Requirement 4 - Severity / category filtering

**Commands:**
```bash
# Terminal 2 - stream open rakha gaya:
cd /home/asad/SGX
A=http://127.0.0.1:18443
curl -N "$A/api/v1/notifications/stream"
```

```bash
# Terminal 1 - medium off, high on:
cd /home/asad/SGX
A=http://127.0.0.1:18443

curl -s -X PUT "$A/api/v1/notifications/prefs" \
  -H "Content-Type: application/json" \
  -d '{"alerts":{"high":true,"medium":false,"low":false}}' | python3 -m json.tool

inject_alert_unique 2 "NOTIF-004 medium should be filtered"
sleep 2
inject_alert_unique 1 "NOTIF-004 high should pass"
sleep 3

curl -s "$A/api/v1/notifications?limit=6" | python3 -m json.tool
```

**Expected:**
```text
alerts.medium=false hone ki wajah se medium event stream par deliver na ho
alerts.high=true hone ki wajah se high event stream par deliver ho
History/store mein dono events persist ho sakte hain
```

**Result:**
```text
Terminal 2 stream output showed only the high event:
event: notification
id: 4
data: {"id":"4","kind":"alert_high","title":"Threat alert on nodeA","body":"NOTIF-004 high should pass from 10.0.0.9:0 to 10.0.0.1:0 (other)","severity":"high","ref_id":"7043c17fbfc6411f","created_at":"2026-07-20T10:14:34.862534812+00:00","read":false}

Terminal 2 did not show:
NOTIF-004 medium should be filtered

History returned both persisted events:
- id: "3", kind: "alert_medium", body includes "NOTIF-004 medium should be filtered"
- id: "4", kind: "alert_high", body includes "NOTIF-004 high should pass"
```

**Verdict:** PASS - stream delivery correctly followed notification preferences: medium filtered, high delivered.

---

## ✅ Requirement 5 - Durability + `Last-Event-ID` replay + restart persistence

**Commands:**
```bash
# Terminal 1 - no SSE client connected for the offline event:
cd /home/asad/SGX
A=http://127.0.0.1:18443

inject_alert_unique 1 "NOTIF-005 offline-1"
sleep 3
curl -s "$A/api/v1/notifications?limit=8" | python3 -m json.tool
```

```bash
# Terminal 2 - replay from an older cursor:
curl -N -H "Last-Event-ID: 4" "$A/api/v1/notifications/stream"
```

```bash
# Terminal 1 - restart persistence proof:
docker restart sgx-nodeA
until curl -sf "$A/api/v1/health" >/dev/null; do sleep 2; done
curl -s "$A/api/v1/notifications?limit=8" | python3 -m json.tool
```

**Expected:**
```text
No active console ke bawajood event store mein persist ho
Reconnect with Last-Event-ID: 4 replay returns newer event(s)
Restart ke baad persisted event history mein available rahe
```

**Result:**
```text
History before restart included:
- id: "5"
- kind: "alert_high"
- body: "NOTIF-005 offline-1 from 10.0.0.9:0 to 10.0.0.1:0 (other)"

SSE replay with Last-Event-ID: 4 returned:
event: notification
id: 5
data: {"id":"5","kind":"alert_high","title":"Threat alert on nodeA","body":"NOTIF-005 offline-1 from 10.0.0.9:0 to 10.0.0.1:0 (other)","severity":"high","ref_id":"1b9e8e8ebd08c7df","created_at":"2026-07-20T10:16:25.055558946+00:00","read":false}

After docker restart sgx-nodeA, history still included id=5.
```

**Verdict:** PASS - offline durability, `Last-Event-ID` replay, aur restart persistence verify ho gaye.

**Note:** Same-second duplicate injection can collapse into one threat inventory event; this PASS uses the confirmed persisted/replayed event `id=5`.

---

## ✅ Requirement 6 - Alerts source wired (Suricata -> notification)

**Commands:**
```bash
cd /home/asad/SGX
A=http://127.0.0.1:18443

curl -s -X PUT "$A/api/v1/notifications/prefs" \
  -H "Content-Type: application/json" \
  -d '{"alerts":{"high":true,"medium":true,"low":true}}' | python3 -m json.tool

inject_alert_unique 1 "NOTIF-006 suricata-high"
sleep 3

curl -s "$A/api/v1/notifications?limit=8" | python3 -m json.tool
docker exec sgx-nodeA sh -lc 'tail -n 8 /var/lib/sgx-guardian/notify/events.jsonl'
```

**Expected:**
```text
Injected EVE alert Suricata/threat tailer path se notification ban kar aaye
severity 1 -> alert_high mapping ho
history aur events.jsonl dono mein event persist ho
```

**Result:**
```text
Prefs update returned alerts.high=true, alerts.medium=true, alerts.low=true with sequence=5.

History returned:
- id: "6"
- kind: "alert_high"
- title: "Threat alert on nodeA"
- body: "NOTIF-006 suricata-high from 10.0.0.9:0 to 10.0.0.1:0 (other)"
- severity: "high"
- read: false

events.jsonl tail contained the same id=6 alert_high event.
```

**Verdict:** PASS - EVE alert source is wired into notification publishing and persistence.

---

## ✅ Requirement 7 - Decoupled future Circle events

**Commands:**
```bash
cd /home/asad/SGX
A=http://127.0.0.1:18443

curl -s "$A/api/v1/notifications/prefs" | python3 -c 'import sys,json; p=json.load(sys.stdin); print("circles keys:", list(p["circles"].keys()))'

curl -s "$A/api/v1/notifications?limit=200" | python3 -c 'import sys,json; d=json.load(sys.stdin); print("circle-kind events:", len([e for e in d if str(e["kind"]).startswith("circle_")]))'

grep -nE "CircleNewMessage|CircleIncomingCall|CircleMemberJoined|CircleFileShared" src/notify/model.rs
```

**Expected:**
```text
Circle preference toggles present hon
Current history mein Circle-kind events 0 hon
Circle event enum variants source model mein defined hon
```

**Result:**
```text
circles keys: ['new_message', 'incoming_call', 'member_joined']
circle-kind events: 0

grep output:
20:    CircleNewMessage,
21:    CircleIncomingCall,
22:    CircleMemberJoined,
23:    CircleFileShared,
33:            Self::CircleNewMessage
34:            | Self::CircleIncomingCall
35:            | Self::CircleMemberJoined
36:            | Self::CircleFileShared => NotificationCategory::Circles,
```

**Verdict:** PASS - Circle preferences exist and persist, Circle event variants are defined, and no Circle source fires events yet.

---

## ✅ API 1 - GET `/api/v1/notifications/stream`

**Commands:**
```bash
curl -N "$A/api/v1/notifications/stream"
inject_alert_unique 1 "NOTIF-003 live push unique"
```

**Expected:**
```text
SSE endpoint text/event-stream behavior de:
- heartbeat comments
- event: notification
- id: <event id>
- data: <notification json>
```

**Result:**
```text
Stream returned:
event: notification
id: 2
data: {"id":"2","kind":"alert_high",...}

Keep-alive ":" frames continued.
```

**Verdict:** PASS - `/api/v1/notifications/stream` endpoint live event stream successfully serve kar raha hai.

---

## ✅ API 2 - GET + PUT `/api/v1/notifications/prefs`

**Commands:**
```bash
curl -s "$A/api/v1/notifications/prefs" | python3 -m json.tool

curl -s -X PUT "$A/api/v1/notifications/prefs" \
  -H "Content-Type: application/json" \
  -d '{"alerts":{"high":true,"medium":false,"low":false}}' | python3 -m json.tool

docker exec sgx-nodeA sh -lc 'cat /var/lib/sgx-guardian/notify/prefs.json' | python3 -m json.tool
docker restart sgx-nodeA
until curl -sf "$A/api/v1/health" >/dev/null; do sleep 2; done
curl -s "$A/api/v1/notifications/prefs" | python3 -m json.tool
```

**Expected:**
```text
GET current prefs de
PUT updated prefs return kare
updated prefs disk par persist hon
restart ke baad same values wapas milen
```

**Result:**
```text
GET succeeded
PUT succeeded
prefs.json updated and signed on disk
restart ke baad same prefs returned
```

**Verdict:** PASS - preferences endpoint pair (`GET` + `PUT`) Docker cohort mein successfully verify hua.

---

## ✅ API 3 - GET `/api/v1/notifications` + `/unread-count`

**Commands:**
```bash
cd /home/asad/SGX
A=http://127.0.0.1:18443

curl -s "$A/api/v1/notifications?limit=8" | python3 -c 'import sys,json; d=json.load(sys.stdin); print("total returned:", len(d)); print("latest:", d[0]["id"], d[0]["kind"], d[0]["read"] if d else "none")'

curl -s "$A/api/v1/notifications/unread-count" | python3 -m json.tool
```

**Expected:**
```text
History endpoint valid JSON array return kare
Unread endpoint {"unread": <count>} return kare
```

**Result:**
```text
total returned: 6
latest: 6 alert_high False

{
    "unread": 6
}
```

**Verdict:** PASS - notification history and unread count APIs return correct live state.

---

## ✅ API 4 - POST `/api/v1/notifications/:id/read` + `/read-all`

**Commands:**
```bash
cd /home/asad/SGX
A=http://127.0.0.1:18443

ID=$(curl -s "$A/api/v1/notifications?limit=1" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d[0]["id"] if d else "")')
echo "$ID"

curl -s -X POST "$A/api/v1/notifications/$ID/read" | python3 -m json.tool
curl -s "$A/api/v1/notifications/unread-count" | python3 -m json.tool

curl -s -X POST "$A/api/v1/notifications/read-all" | python3 -m json.tool
curl -s "$A/api/v1/notifications/unread-count" | python3 -m json.tool
```

**Expected:**
```text
Latest notification id read mark ho
updated=true return ho
unread count one step drop ho
read-all ke baad unread=0 ho
```

**Result:**
```text
Selected ID:
6

POST /notifications/6/read:
{
    "updated": true,
    "unread": 5
}

GET /notifications/unread-count:
{
    "unread": 5
}

POST /notifications/read-all:
{
    "marked": 5,
    "unread": 0
}

GET /notifications/unread-count:
{
    "unread": 0
}
```

**Verdict:** PASS - mark-read and read-all APIs update persisted read state and unread count correctly.

---

## ✅ API 5 - Security - tampered `prefs.json` rejected

**Commands:**
```bash
cd /home/asad/SGX
A=http://127.0.0.1:18443

docker cp sgx-nodeA:/var/lib/sgx-guardian/notify/prefs.json /tmp/notif-prefs-good.json
cp /tmp/notif-prefs-good.json /tmp/notif-prefs-tampered.json

python3 -c 'import json; p=json.load(open("/tmp/notif-prefs-tampered.json")); p["alerts"]["high"]=False; json.dump(p, open("/tmp/notif-prefs-tampered.json","w"))'

docker cp /tmp/notif-prefs-tampered.json sgx-nodeA:/var/lib/sgx-guardian/notify/prefs.json

curl -i "$A/api/v1/notifications/prefs"
```

**Expected:**
```text
Tampered prefs silently accept na hon
API fail-closed behavior show kare, e.g. HTTP 500/internal error
```

**Result:**
```text
HTTP/1.1 500 Internal Server Error
content-type: application/json
vary: origin, access-control-request-method, access-control-request-headers
access-control-allow-origin: http://localhost:3000
content-length: 51
date: Mon, 20 Jul 2026 10:46:12 GMT

{"code":"INTERNAL","error":"internal server error"}
```

**Verdict:** PASS - tampered unsigned `prefs.json` was rejected; modified preference was not silently honored.

**Restore command:**
```bash
docker cp /tmp/notif-prefs-good.json sgx-nodeA:/var/lib/sgx-guardian/notify/prefs.json
docker restart sgx-nodeA
until curl -sf "$A/api/v1/health" >/dev/null; do sleep 2; done
curl -s "$A/api/v1/notifications/prefs" | python3 -m json.tool
```

---

## 🎯 Next PASS Target

Verification complete for this Docker run:

- Requirements: `7/7`
- APIs: `5/5`

Final cleanup/restore should still be run if it was not already run after API 5.

---

## ✅ Fresh API 1-5 Recheck - 2026-08-03

**Mode:** Temporary `SGX_DISABLE_LOGIN=1` Docker verification mode on `sgx-nodeA`, followed by normal auth-enabled restore.

**Result:**
```text
API 1 - SSE:
SSE received id=13 kind=alert_high read=false
body includes "API1 fresh SSE 1785749196"

API 2 - prefs GET/PUT:
before_sequence: 6
guardian_offline false -> true
PUT response sequence: 7
disk prefs.json proof_present: True
restart preserved guardian_offline=true
restored guardian_offline=false, sequence: 8

API 3 - history + unread-count:
total returned: 13
latest: 13 alert_high False
computed_unread: 1
unread-count: {"unread": 1}

API 4 - mark-read + read-all:
fresh event body includes "API4 fresh mark-read 1785749318"
before_unread: 2
selected_id: 14
POST /notifications/14/read -> {"updated": true, "unread": 1}
POST /notifications/read-all -> {"marked": 1, "unread": 0}
after restart unread-count -> {"unread": 0}
latest_read_state_after_restart: 14 True

API 5 - tampered prefs rejected:
tampered alerts.high True -> False with old proof still present
GET /notifications/prefs after tamper -> HTTP 500
error: notify: did: DID document signature invalid
restored signed prefs -> HTTP 200

Final restore:
normal compose nodeA health -> HTTP 200
SGX_DISABLE_LOGIN=<unset>
unauthenticated prefs endpoint -> HTTP 401
```

**Verdict:** PASS - APIs 1-5 were re-tested end-to-end; tampered prefs were rejected and the Docker cohort ended back in normal auth-enabled mode.
