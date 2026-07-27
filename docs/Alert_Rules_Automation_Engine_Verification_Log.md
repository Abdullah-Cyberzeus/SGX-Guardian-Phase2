# Custom Alert Rules / Automation Engine — Verification Log
**Board:** nodeA (192.168.50.115) — iMX8MP (ARM64)  ·  *(optional peer for event traffic: nodeB 192.168.50.248)* | **Date:** ______ | **Tester:** Asad Ali
**Test tag:** RULES-series (RULES-001 – RULES-009) | **Plan:** `Alert_Rules_Automation_Engine_Complete_Plan.md`

---

## 📌 Task Description

> Implement an event→condition→action rule engine supporting alert rule creation, modification, execution workflows, action handlers, and rule lifecycle management. Condition evaluation is a **pure, side-effect-free** function (same discipline as the existing `Blocker::should_block`), executed off the event-producing path. Actions come from a **fixed catalog** (no shell/scripts) and call internal entry points. **Every block inherits `Blocker`'s self-protection** (live local-interface subnets + default gateway + `block_exempt`) so a rule can never lock the operator out. Safe by default: **dry-run on** (`SGX_RULES_DRYRUN=1`), destructive actions opt-in per rule, per-rule cooldown + hourly rate cap, signed rule registry (fail-closed on tamper). No new port — REST rides `:8443`.

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
   - Kya rules engine start hui (`grep -a "rules engine\|Rules" /var/log/sgx-guardian/audit-nodeA.log`)?
   - **Rule fire nahi hui?** — kya rule `enabled: true` hai, kya `trigger` event ke type se match karta hai, aur kya `condition` sach hai? `POST /rules/:id/test` se pehle dry-run karke dekho rule *fire hoti bhi hai ya nahi*
   - **Action nahi chali?** — dry-run to on nahi (`SGX_RULES_DRYRUN`, default **1 = safe**)? Ye expected behavior hai, bug nahi
   - **Destructive action downgrade ho gayi?** — `allow_destructive` false hoga (default). Ye bhi expected hai
   - **Kuch bhi fire nahi hua burst pe?** — cooldown (`cooldown_secs`, default 300) ya rate cap (`max_actions_per_hour`, default 20) laga hoga; `GET /rules/executions` mein outcome dekho
   - Suricata event source ke liye — kya threat engine chal raha hai? Warna alert generate hi nahi hoga
   - Alternate command / dobara try karo
2. **Sirf tab `❌` lagao** jab fully confirm ho jaye ke issue code side ka hai, command side ka nahi
3. **`❌` lagane ke saath ye bhi likho:**
   - Konsi file/function mein likely issue hai (e.g. `src/rules/eval.rs` [condition matching], `src/rules/store.rs` [registry/signature], `src/rules/bus.rs` [event ingestion], `src/rules/exec/actions.rs` [executors], `src/rules/exec/guards.rs` [dry-run/cooldown/destructive gate]) (cross-check khud bhi karo — issue doosri file mein bhi ho sakta hai)
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
export SGX_RULES_DRYRUN=1                 # SAFE default — destructive actions only audited
export SGX_RULES_MAX_EXECUTIONS=2000
./sgx_guardian_client nodeA

# Handy variables:
API=http://localhost:8443/api/v1
RULES_DIR=/var/lib/sgx-guardian/rules      # rules.json + executions.jsonl + state.json
GW=$(ip route | awk '/default/{print $3; exit}')          # default gateway — MUST never get blocked
LAN=$(ip -o -f inet addr show | awk '/192.168.50/{print $4; exit}')   # management LAN CIDR

# Confirm engine started + dir exists:
grep -a "rules engine\|Rules" /var/log/sgx-guardian/audit-nodeA.log | tail -1
ls -l "$RULES_DIR"
echo "gateway=$GW  management-lan=$LAN"

# --- Test event injector (Suricata alert = the primary live trigger) ---
# EVE line inject karte hain jo tailer read karke forward_to_ai + rules::publish tak pohchati hai.
# (EVE path apni Suricata config se confirm karo — default niche.)
EVE_LOG=/opt/suricata/var/log/eve.json
inject_alert () {  # usage: inject_alert <severity 1|2|3> <src_ip> <signature>
  printf '{"timestamp":"%s","event_type":"alert","src_ip":"%s","dest_ip":"10.0.0.1","proto":"TCP","alert":{"severity":%s,"signature":"%s","category":"Test","signature_id":9990002}}\n' \
    "$(date -u +%FT%T.000000+0000)" "$2" "$1" "$3" >> "$EVE_LOG"
}
```

> **Notes:**
> - Ye feature **per-Guardian local** hai — rules isi node pe evaluate aur execute hoti hain. CRL gossip ki tarah cross-node propagation **nahi** hai (by design). Zyada-tar requirements **nodeA single-node** pe run hoti hain.
> - **Dry-run default hai** (`SGX_RULES_DRYRUN=1`). Matlab destructive actions **audit** hongi (`would-run`) magar **execute nahi**. Jab tak E5 board pe verify na ho, dry-run OFF **mat** karo.
> - **Safe test IP use karo** blocking tests ke liye — kabhi `$GW` ya apni management LAN ka IP block karne ki koshish sirf **self-protection test (RULES-005)** mein karo, jahan **refusal expected hai**.

---

## ⏳ Requirement 1 — [ ] Event→condition→action model + pure condition evaluation

> Rule ka shape: `trigger` (When) + `condition` (If) + `actions` (Then). Condition evaluation **pure** hai — koi nftables/network/SE050 touch nahi (unit test bina hardware ke chalta hai), bilkul `Blocker::should_block` ki tarah.

**Commands (host + nodeA):**
```bash
# Host — pure evaluator unit matrix (mirrors threat_blocker_logic_test.rs):
cargo test --package sgx-guardian-client rules::eval
# Expect: All/Any/Not nesting, SeverityAtLeast, SrcIpInCidr boundary cases — all pass,
#         and the test runs WITHOUT nftables/network/SE050 present

# Board — create a rule with a compound condition:
RID=$(curl -s -X POST "$API/rules" -H 'content-type: application/json' -d '{
  "name":"RULES-001 high alerts",
  "trigger":"ThreatAlert",
  "condition":{"All":[{"SeverityAtLeast":"high"},{"Not":{"SrcIpInCidr":"127.0.0.0/8"}}]},
  "actions":[{"RaiseAlert":{"severity":"high"}}],
  "notify":true}' | python3 -c "import sys,json;print(json.load(sys.stdin)['rule_id'])")
echo "RID=$RID"
curl -s "$API/rules/$RID" | python3 -m json.tool
```

**Expected:**
```
Unit: (rule, event) → expected bool matrix passes; evaluator is pure (no I/O)
Board: rule stored with trigger=ThreatAlert, nested All/Not condition, actions=[RaiseAlert]
Defaults applied: enabled=true, allow_destructive=false, cooldown_secs=300, max_actions_per_hour=20
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

---

## ⏳ Requirement 2 — [ ] Rule creation, modification & lifecycle management

> Create / read / update / delete + enable-disable toggle. Registry **signed** aur atomically persisted; restart ke baad rules survive karti hain.

**Commands (nodeA):**
```bash
# List + modify:
curl -s "$API/rules" | python3 -c "import sys,json;[print(r['rule_id'],r['name'],'enabled=',r['enabled']) for r in json.load(sys.stdin)]"
curl -s -X PATCH "$API/rules/$RID" -H 'content-type: application/json' \
  -d '{"name":"RULES-002 renamed","cooldown_secs":60}' | python3 -m json.tool

# Disable / enable:
curl -s -X POST "$API/rules/$RID/enable" -H 'content-type: application/json' -d '{"enabled":false}' | python3 -m json.tool
curl -s "$API/rules/$RID" | python3 -c "import sys,json;print('enabled:',json.load(sys.stdin)['enabled'])"
curl -s -X POST "$API/rules/$RID/enable" -H 'content-type: application/json' -d '{"enabled":true}' >/dev/null

# On disk — signed registry:
python3 -c "import json;r=json.load(open('$RULES_DIR/rules.json'));print('rules:',len(r['rules']));print('has_proof:', 'proof' in r);print('seq:',r.get('sequence'))"

# Restart → rules persist:
pkill -f sgx_guardian_client && sleep 3 && ./sgx_guardian_client nodeA &
sleep 8
curl -s "$API/rules" | python3 -c "import sys,json;print('rules after restart:',len(json.load(sys.stdin)))"

# Delete (cleanup at the end of testing):
# curl -s -o /dev/null -w '%{http_code}\n' -X DELETE "$API/rules/$RID"
```

**Expected:**
```
POST/GET/PATCH/DELETE + enable toggle all work
rules.json signed (proof present), sequence increments on each mutation
After restart rules still present — atomic persistence
Disabled rule does NOT evaluate (verify in Req 3 by injecting while disabled)
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

---

## ⏳ Requirement 3 — [ ] Event ingestion (live sources, non-blocking)

> Suricata alert engine tak pohnchti hai (`rules::publish` — `forward_to_ai` ke bilkul saath, non-blocking). Producing loop block **nahi** hota — alert load ke doran API responsive rehta hai.

**Commands (nodeA):**
```bash
# Rule enabled hai, ab ek matching alert inject karo:
inject_alert 1 "203.0.113.50" "RULES-003 ingestion probe"
sleep 3
curl -s "$API/rules/executions" | python3 -c "import sys,json;d=json.load(sys.stdin);print('executions:',len(d));[print(e['rule_name'],e['outcome']) for e in d[-3:]]"

# Non-blocking proof — burst of alerts, API must stay responsive throughout:
for i in $(seq 1 30); do inject_alert 1 "203.0.113.$i" "RULES-003 burst $i"; done
time curl -s -o /dev/null -w 'health HTTP %{http_code} in %{time_total}s\n' "$API/health"

# Disabled-rule check (lifecycle from Req 2):
curl -s -X POST "$API/rules/$RID/enable" -H 'content-type: application/json' -d '{"enabled":false}' >/dev/null
inject_alert 1 "203.0.113.99" "RULES-003 should NOT fire"
sleep 3
curl -s "$API/rules/executions" | python3 -c "import sys,json;print('last:',json.load(sys.stdin)[-1]['trigger_summary'])"
curl -s -X POST "$API/rules/$RID/enable" -H 'content-type: application/json' -d '{"enabled":true}' >/dev/null
```

**Expected:**
```
Matching alert → execution recorded for the rule
30-alert burst → /health still answers fast (producing loop not blocked, publish is non-blocking)
Disabled rule → NO new execution for the injected alert
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

---

## ⏳ Requirement 4 — [ ] Action handlers (fixed catalog, internal entry points)

> Non-destructive actions actually run: `RaiseAlert`, `Notify`, `RunScan`. Executors internal functions call karte hain (HTTP round-trip nahi). Action catalog **fixed enum** hai — koi shell/script/user command nahi.

**Commands (nodeA):**
```bash
# Rule ko multi-action bana do (non-destructive only):
curl -s -X PATCH "$API/rules/$RID" -H 'content-type: application/json' -d '{
  "actions":[{"RaiseAlert":{"severity":"high"}},{"Notify":{"severity":"high"}}]}' | python3 -m json.tool

inject_alert 1 "203.0.113.60" "RULES-004 action handlers"
sleep 4

# Executions show both actions:
curl -s "$API/rules/executions" | python3 -c "import sys,json;e=json.load(sys.stdin)[-1];print('actions:',e['actions']);print('outcome:',e['outcome'])"

# RaiseAlert landed as a real alert; Notify reached the notification bus (if notify built):
curl -s "$API/threat/alerts?limit=3" | python3 -c "import sys,json;print('threat alerts:',len(json.load(sys.stdin)))"
curl -s "$API/notifications" 2>/dev/null | python3 -c "import sys,json;print('notifications:',len(json.load(sys.stdin)))" 2>/dev/null || echo "notify feature not built yet — seam only"

# Fixed catalog — an unknown/arbitrary action must be REJECTED (no RCE surface):
curl -s -o /dev/null -w 'arbitrary action HTTP %{http_code}\n' -X PATCH "$API/rules/$RID" \
  -H 'content-type: application/json' -d '{"actions":[{"RunShell":{"cmd":"/bin/sh -c id"}}]}'   # expect 4xx
```

**Expected:**
```
Both actions recorded in the execution entry; outcome=executed (non-destructive run even in dry-run,
  OR audited per plan's dry-run policy — record which behaviour was observed)
RaiseAlert visible as an alert; Notify reached the bus (or seam-only if notify not built)
Arbitrary/unknown action → 4xx rejected (fixed enum, no shell)
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

---

## ⏳ Requirement 5 — [ ] Self-protection inherited (gateway / management LAN / overlay never blocked) ⚠ CRITICAL

> **Sabse zaroori test.** `BlockIp` action `Blocker` ke through jata hai, jo live local-interface subnets + default gateway + `block_exempt` (loopback, Nebula overlay) ko **kabhi block nahi** karta. Ek rule operator ko lock out **nahi** kar sakti.

**Commands (nodeA):**
```bash
echo "gateway=$GW  management-lan=$LAN"

# Rule ko BlockIp action de do:
curl -s -X PATCH "$API/rules/$RID" -H 'content-type: application/json' \
  -d '{"actions":[{"BlockIp":{"ttl_secs":600}}],"cooldown_secs":0}' | python3 -m json.tool

# 1) GATEWAY ko target karo — refusal expected:
inject_alert 1 "$GW" "RULES-005 gateway block attempt"
sleep 4

# 2) Management LAN host ko target karo — refusal expected:
inject_alert 1 "192.168.50.200" "RULES-005 mgmt-lan block attempt"
sleep 4

# 3) Nebula overlay ko target karo — refusal expected:
inject_alert 1 "192.168.100.5" "RULES-005 overlay block attempt"
sleep 4

# VERIFY — none of these may appear in the block list:
curl -s "$API/threat/blocks" | python3 -m json.tool
nft list chain inet sgx_threat input 2>/dev/null | grep -E "$GW|192.168.50|192.168.100" || echo "OK: no protected address blocked"

# Audit must show the refusal + reason:
grep -a "exempt\|refused to block\|self-protect" /var/log/sgx-guardian/audit-nodeA.log | tail -5

# Executions show the outcome (refused/downgraded, not executed):
curl -s "$API/rules/executions" | python3 -c "import sys,json;[print(e['trigger_summary'],'->',e['outcome']) for e in json.load(sys.stdin)[-3:]]"

# 4) CONTROL — a safe external IP SHOULD be blockable (proves the action works at all):
inject_alert 1 "203.0.113.77" "RULES-005 safe block control"
sleep 4
curl -s "$API/threat/blocks" | python3 -c "import sys,json;print('blocked:',json.load(sys.stdin)['blocked'])"
# cleanup:
curl -s -X POST "$API/threat/blocks/unblock" -H 'content-type: application/json' -d '{"ip":"203.0.113.77"}' >/dev/null
```

**Expected:**
```
Gateway / 192.168.50.0/24 / 192.168.100.0/24 → NEVER blocked (refused + audited)
Board still reachable throughout (SSH / API not lost)
Control case: 203.0.113.77 IS blocked — the action itself works, only protected ranges are exempt
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

---

## ⏳ Requirement 6 — [ ] Safeguards: dry-run, destructive gate, cooldown, rate cap ⚠ CRITICAL

> (a) **Dry-run default** — destructive action execute nahi hoti, sirf `would-run` audit. (b) **Destructive gate** — `allow_destructive=false` ho to critical alert mein **downgrade**. (c) **Cooldown** — same target pe re-fire block. (d) **Rate cap** — alert storm pe actions ceiling tak.

**Commands (nodeA):**
```bash
echo "SGX_RULES_DRYRUN=$SGX_RULES_DRYRUN  (must be 1 for this test)"

# (a) DRY-RUN — destructive action must NOT execute. DKP version is the proof:
DKP_BEFORE=$(curl -s "$API/dkp/status" | python3 -c "import sys,json;print(json.load(sys.stdin).get('version'))")
curl -s -X PATCH "$API/rules/$RID" -H 'content-type: application/json' \
  -d '{"actions":[{"EmergencyKeyRotation":null}],"allow_destructive":true,"cooldown_secs":0}' >/dev/null
inject_alert 1 "203.0.113.80" "RULES-006 dryrun destructive"
sleep 5
DKP_AFTER=$(curl -s "$API/dkp/status" | python3 -c "import sys,json;print(json.load(sys.stdin).get('version'))")
echo "DKP BEFORE=$DKP_BEFORE AFTER=$DKP_AFTER  (MUST be equal — dry-run did not rotate)"
grep -a "would-run\|dry-run" /var/log/sgx-guardian/audit-nodeA.log | tail -3

# (b) DESTRUCTIVE GATE — allow_destructive=false → downgraded to critical alert:
curl -s -X PATCH "$API/rules/$RID" -H 'content-type: application/json' \
  -d '{"allow_destructive":false}' >/dev/null
inject_alert 1 "203.0.113.81" "RULES-006 gate downgrade"
sleep 4
curl -s "$API/rules/executions" | python3 -c "import sys,json;e=json.load(sys.stdin)[-1];print('outcome:',e['outcome'])"   # expect 'downgraded'

# (c) COOLDOWN — same target twice inside cooldown fires once:
curl -s -X PATCH "$API/rules/$RID" -H 'content-type: application/json' \
  -d '{"actions":[{"RaiseAlert":{"severity":"high"}}],"cooldown_secs":300}' >/dev/null
BEFORE=$(curl -s "$API/rules/executions" | python3 -c "import sys,json;print(len(json.load(sys.stdin)))")
inject_alert 1 "203.0.113.90" "RULES-006 cooldown A"; sleep 3
inject_alert 1 "203.0.113.90" "RULES-006 cooldown B"; sleep 3
AFTER=$(curl -s "$API/rules/executions" | python3 -c "import sys,json;print(len(json.load(sys.stdin)))")
echo "executions BEFORE=$BEFORE AFTER=$AFTER  (should grow by 1, not 2 — cooldown held)"

# (d) RATE CAP — 50 rapid alerts must not produce 50 actions:
curl -s -X PATCH "$API/rules/$RID" -H 'content-type: application/json' \
  -d '{"cooldown_secs":0,"max_actions_per_hour":20}' >/dev/null
B2=$(curl -s "$API/rules/executions" | python3 -c "import sys,json;print(len([e for e in json.load(sys.stdin) if e['outcome']=='executed']))")
for i in $(seq 1 50); do inject_alert 1 "198.51.100.$i" "RULES-006 storm $i"; done
sleep 10
A2=$(curl -s "$API/rules/executions" | python3 -c "import sys,json;print(len([e for e in json.load(sys.stdin) if e['outcome']=='executed']))")
echo "executed BEFORE=$B2 AFTER=$A2  (delta must be <= max_actions_per_hour = 20)"
curl -s "$API/rules/executions" | python3 -c "import sys,json;from collections import Counter;print(Counter(e['outcome'] for e in json.load(sys.stdin)))"
```

**Expected:**
```
(a) DKP version UNCHANGED in dry-run; audit shows 'would-run'
(b) allow_destructive=false → outcome 'downgraded' (critical alert raised instead)
(c) Cooldown: two identical triggers → one execution
(d) Rate cap: 50 alerts → executed actions capped at 20; rest 'rate-limited'
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

---

## ⏳ Requirement 7 — [ ] Execution workflow, history & fail-safe isolation

> Har fire ka record: rule, trigger summary, actions, outcome (`executed`/`dry-run`/`downgraded`/`rate-limited`/`failed`). Dispatch **separate task** pe hota hai (engine block nahi hota), aur ek failing action baaki actions ya daemon ko nahi girata.

**Commands (nodeA):**
```bash
# History shape:
curl -s "$API/rules/executions" | python3 -c "
import sys,json
d=json.load(sys.stdin); print('total:',len(d))
print('keys:',sorted(d[-1].keys()))
for e in d[-5:]: print(' ',e['rule_name'],'|',e['trigger_summary'],'|',e['actions'],'->',e['outcome'])"

# Ring cap honoured (SGX_RULES_MAX_EXECUTIONS):
wc -l "$RULES_DIR/executions.jsonl"

# Fail-safe: multi-action rule where one action fails — others still run, daemon survives
curl -s -X PATCH "$API/rules/$RID" -H 'content-type: application/json' -d '{
  "actions":[{"RunScan":{"intensity":"invalid-intensity"}},{"RaiseAlert":{"severity":"high"}}],
  "cooldown_secs":0}' >/dev/null
inject_alert 1 "203.0.113.95" "RULES-007 failsafe"
sleep 6
curl -s "$API/rules/executions" | python3 -c "import sys,json;e=json.load(sys.stdin)[-1];print('actions:',e['actions'],'outcome:',e['outcome'])"
grep -a "action failed\|Rules" /var/log/sgx-guardian/audit-nodeA.log | tail -3
curl -s -o /dev/null -w 'health HTTP %{http_code}\n' "$API/health"   # daemon alive
pgrep -f sgx_guardian_client >/dev/null && echo "daemon still running"

# Executions survive restart:
pkill -f sgx_guardian_client && sleep 3 && ./sgx_guardian_client nodeA &
sleep 8
curl -s "$API/rules/executions" | python3 -c "import sys,json;print('executions after restart:',len(json.load(sys.stdin)))"
```

**Expected:**
```
Each execution: rule_id/rule_name, trigger_summary, actions[], outcome, timestamp
Failing action isolated + audited; the sibling RaiseAlert still ran; daemon alive (no panic/freeze)
executions.jsonl capped at SGX_RULES_MAX_EXECUTIONS; survives restart
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

---

# 🔌 API Verification — New Endpoints

## ⏳ API 1 — [ ] Rule CRUD — `GET/POST /api/v1/rules`, `GET/PATCH/DELETE /api/v1/rules/:id`

**Command:**
```bash
curl -s "$API/rules" | python3 -m json.tool
curl -s -X POST "$API/rules" -H 'content-type: application/json' -d '{
  "name":"API1 test","trigger":"ThreatAlert",
  "condition":{"SeverityAtLeast":"high"},
  "actions":[{"RaiseAlert":{"severity":"high"}}],"notify":false}' | python3 -m json.tool
TMP=$(curl -s "$API/rules" | python3 -c "import sys,json;print(json.load(sys.stdin)[-1]['rule_id'])")
curl -s "$API/rules/$TMP" | python3 -m json.tool
curl -s -X PATCH "$API/rules/$TMP" -H 'content-type: application/json' -d '{"name":"API1 renamed"}' | python3 -m json.tool
curl -s -o /dev/null -w 'DELETE HTTP %{http_code}\n' -X DELETE "$API/rules/$TMP"
```

**Expected:**
```
GET list → rules array ; POST → 201 with rule_id + safe defaults
GET detail → full rule ; PATCH → updated + sequence bumped ; DELETE → 200 and gone from list
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

## ⏳ API 2 — [ ] POST `/api/v1/rules/:id/enable`

**Command:**
```bash
curl -s -X POST "$API/rules/$RID/enable" -H 'content-type: application/json' -d '{"enabled":false}' | python3 -m json.tool
curl -s "$API/rules/$RID" | python3 -c "import sys,json;print('enabled:',json.load(sys.stdin)['enabled'])"
curl -s -X POST "$API/rules/$RID/enable" -H 'content-type: application/json' -d '{"enabled":true}' | python3 -m json.tool
```

**Expected:**
```
Toggle persists to rules.json (signed, sequence bumped); disabled rule does not evaluate
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

## ⏳ API 3 — [ ] POST `/api/v1/rules/:id/test` (dry-run, no side effects)

**Command:**
```bash
# Capture state before:
BLOCKS_BEFORE=$(curl -s "$API/threat/blocks" | python3 -c "import sys,json;print(len(json.load(sys.stdin)['blocked']))")
EXEC_BEFORE=$(curl -s "$API/rules/executions" | python3 -c "import sys,json;print(len(json.load(sys.stdin)))")

curl -s -X POST "$API/rules/$RID/test" -H 'content-type: application/json' -d '{
  "sample_event":{"trigger":"ThreatAlert","severity":"high","src_ip":"203.0.113.10","signature_id":9990002}}' | python3 -m json.tool

# Nothing changed:
BLOCKS_AFTER=$(curl -s "$API/threat/blocks" | python3 -c "import sys,json;print(len(json.load(sys.stdin)['blocked']))")
EXEC_AFTER=$(curl -s "$API/rules/executions" | python3 -c "import sys,json;print(len(json.load(sys.stdin)))")
echo "blocks $BLOCKS_BEFORE->$BLOCKS_AFTER  executions $EXEC_BEFORE->$EXEC_AFTER  (both must be unchanged)"
```

**Expected:**
```
Returns would-fire verdict + the action plan (what WOULD run)
No block added, no execution recorded — test is side-effect free
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

## ⏳ API 4 — [ ] GET `/api/v1/rules/executions`

**Command:**
```bash
curl -s "$API/rules/executions" | python3 -c "
import sys,json
from collections import Counter
d=json.load(sys.stdin)
print('total:',len(d))
print('outcomes:',Counter(e['outcome'] for e in d))
print('sample:',d[-1] if d else 'none')"
```

**Expected:**
```
Array of RuleExecution: id, rule_id, rule_name, trigger_summary, actions[], outcome, at
Outcomes seen across testing: executed | dry-run | downgraded | rate-limited | failed
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

## ⏳ API 5 — [ ] Security — tampered `rules.json` rejected (fail-closed, NO rules run)

> Registry ki ek value flip karke daemon restart — signed registry invalid ho jaani chahiye, aur **koi rule nahi chalni chahiye** (fail-closed), warna attacker apni rule inject kar ke actions chala sakta hai.

**Command (nodeA):**
```bash
cp "$RULES_DIR/rules.json" /tmp/rules.bak
# Tamper: inject a destructive rule without re-signing
python3 -c "
import json
r=json.load(open('$RULES_DIR/rules.json'))
if r['rules']:
    r['rules'][0]['allow_destructive']=True
    r['rules'][0]['actions']=[{'EmergencyKeyRotation':None}]
json.dump(r,open('$RULES_DIR/rules.json','w'))"
pkill -f sgx_guardian_client && sleep 3 && ./sgx_guardian_client nodeA & sleep 8

# Audit shows rejection; NO rules loaded:
grep -a "rules.*invalid\|rules.*signature\|rule registry rejected" /var/log/sgx-guardian/audit-nodeA.log | tail -3
curl -s "$API/rules" | python3 -c "import sys,json;print('rules loaded:',len(json.load(sys.stdin)))"

# Confirm the injected destructive rule did NOT run:
DKP_NOW=$(curl -s "$API/dkp/status" | python3 -c "import sys,json;print(json.load(sys.stdin).get('version'))")
inject_alert 1 "203.0.113.120" "RULES-009 tampered rule must not fire"
sleep 5
DKP_AFT=$(curl -s "$API/dkp/status" | python3 -c "import sys,json;print(json.load(sys.stdin).get('version'))")
echo "DKP $DKP_NOW -> $DKP_AFT (must be equal — tampered rule never ran)"

# RESTORE:
cp /tmp/rules.bak "$RULES_DIR/rules.json" && pkill -f sgx_guardian_client && sleep 3 && ./sgx_guardian_client nodeA &
```

**Expected:**
```
Tampered rules.json → signature invalid → fail-closed: 0 rules loaded, audit line present
Injected destructive rule NEVER executes (DKP version unchanged)
After restore, rules load normally again
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

---

## 🗺️ Test-Tag Mapping (RULES-series)

| Tag | What it proves | Section above |
|---|---|---|
| RULES-001 | Event→condition→action model + pure evaluation | Req 1 |
| RULES-002 | Rule creation / modification / lifecycle (signed, persisted) | Req 2 |
| RULES-003 | Event ingestion, non-blocking; disabled rule inert | Req 3 |
| RULES-004 | Action handlers (fixed catalog, internal entry points) | Req 4 |
| RULES-005 | **Self-protection — gateway / LAN / overlay never blocked** ⚠ | Req 5 |
| RULES-006 | **Safeguards — dry-run, destructive gate, cooldown, rate cap** ⚠ | Req 6 |
| RULES-007 | Execution history + fail-safe isolation | Req 7 |
| RULES-008 | CRUD / enable / test / executions APIs | API 1–4 |
| RULES-009 | Tampered rule registry rejected (fail-closed) | API 5 |

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
RULES_DIR=/var/lib/sgx-guardian/rules

# Engine alive? (startup line)
grep -a "rules engine\|Rules" /var/log/sgx-guardian/audit-nodeA.log | tail -1

# API reachable?
curl -s "$API/health" | python3 -m json.tool

# Rules + executions + guard state on disk:
cat "$RULES_DIR/rules.json" | python3 -m json.tool | head -40
wc -l "$RULES_DIR/executions.jsonl" 2>/dev/null
cat "$RULES_DIR/state.json" 2>/dev/null | python3 -m json.tool     # cooldown / rate counters

# Is dry-run actually on? (safety check before ANY destructive test)
echo "SGX_RULES_DRYRUN=$SGX_RULES_DRYRUN  (1 = safe, actions only audited)"

# 🚑 PANIC BUTTON — disable ALL rules immediately (no code change needed):
for r in $(curl -s "$API/rules" | python3 -c "import sys,json;[print(x['rule_id']) for x in json.load(sys.stdin)]"); do
  curl -s -X POST "$API/rules/$r/enable" -H 'content-type: application/json' -d '{"enabled":false}' >/dev/null
done
echo "all rules disabled"

# 🚑 If a block went wrong — inspect and clear:
curl -s "$API/threat/blocks" | python3 -m json.tool
curl -s -X POST "$API/threat/blocks/unblock" -H 'content-type: application/json' -d '{"ip":"<IP>"}'
nft list chain inet sgx_threat input        # what is actually in the kernel

# Full rules trail:
grep -a "Rules\|rule fired\|would-run\|downgraded\|rate-limited\|exempt" /var/log/sgx-guardian/audit-nodeA.log | tail -20

# Threat pipeline unharmed (we wired NEXT TO, not INTO, forward_to_ai):
curl -s "$API/threat/alerts?limit=5" | python3 -c "import sys,json;print('threat alerts:',len(json.load(sys.stdin)))"

# Confirm EVE tailer / threat engine running (needed for the ThreatAlert trigger):
pgrep -f suricata ; ls -l /opt/suricata/var/log/eve.json

# Reset rules test state (history only; rules preserved):
pkill -f sgx_guardian_client
rm -f "$RULES_DIR/executions.jsonl" "$RULES_DIR/state.json"
./sgx_guardian_client nodeA

# Isolate a clean test run (empty rules dir override):
SGX_GUARDIAN_RULES_BASE=/tmp/rules-test ./sgx_guardian_client nodeA
```

**Timing cheat-sheet:** rule evaluation is event-driven → a matching event fires within ~1–3 s of injection · no interval to wait for (unlike gossip) · **cooldown default 300 s** — set `cooldown_secs: 0` when testing repeat fires · **rate cap 20/hour** — a burst test will hit it by design · dry-run is ON by default, so destructive actions will *never* execute until it is explicitly turned off · ThreatAlert trigger needs the Suricata/EVE pipeline live.

---

## 🔗 Cross-feature note

Engine ka **primary live trigger** abhi threat pipeline hai (Suricata → `rules::publish` next to `forward_to_ai`). Discovery / geofence / attestation / CRL seams isi one-line pattern se wire hote hain. **Blocking hamesha `Blocker` ke through** jata hai — isliye self-protection (live local subnets + default gateway + `block_exempt`) automatically inherit hoti hai; rules module khud kabhi `nft` ko call nahi karta. Action catalog **fixed enum** hai (no shell/scripts) — RCE surface nahi. Notification feature build ho jaye to `Notify` action live console tak pohnchega; abhi woh seam hai.
