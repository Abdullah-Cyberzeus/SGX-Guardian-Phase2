# Data Usage Monitoring — Verification Log
**Board:** nodeA (192.168.50.115) — iMX8MP (ARM64)  ·  *(traffic peer: nodeB 192.168.50.248)* | **Date:** ______ | **Tester:** Aliza Malik
**Test tag:** DUSAGE-series (DUSAGE-001 – DUSAGE-009) | **Plan:** `Data_Usage_Monitoring_Complete_Plan.md`

---

## 📌 Task Description

> Implement per-device and per-category bandwidth monitoring, quota tracking, usage history, analytics, and reset scheduling. **Correction verified during grounding:** nftables rules do **not** carry counters today (plain accept/drop) — the primary, zero-change source is `/sys/class/net/*/statistics/*` (per-interface); per-category needs `counter` statements **added** to enforcement (D5); per-device (per-IP) is the harder conntrack/IP-keyed path (optional D6). Usage is period-relative (`current − baseline`) and **reset-safe** (a reboot/counter-flush must not produce a negative or spurious spike). No new port — REST rides `:8443`.

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
   - Kya sampler task start hui (`grep -a "Data-usage\|dusage" /var/log/sgx-guardian/audit-nodeA.log`)?
   - Counters test ke liye — kya **sample interval** guzra (`SGX_DUSAGE_SAMPLE_SECS`, default 60)? Usage next sample par hi update hoti hai
   - Traffic test ke liye — kya actually bytes gaye (interface pe real traffic)? `/sys` counters zero rehte hain agar traffic hi nahi
   - Per-category (DUSAGE-002) ke liye — kya D5 built hai aur nft counters declared hain (`nft list counters`)?
   - Alternate command / dobara try karo
2. **Sirf tab `❌` lagao** jab fully confirm ho jaye ke issue code side ka hai, command side ka nahi
3. **`❌` lagane ke saath ye bhi likho:**
   - Konsi file/function mein likely issue hai (e.g. `src/dusage/counters.rs` [/sys read], `src/dusage/sampler.rs` [baseline/rollover], `src/dusage/quota.rs` [used_pct], `src/api/handlers/dusage.rs`) (cross-check khud bhi karo)
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
export SGX_DUSAGE_SAMPLE_SECS=15          # short interval for faster testing (plan default 60)
export SGX_DUSAGE_PERIOD=monthly
./sgx_guardian_client nodeA

# Handy variables:
API=http://localhost:8443/api/v1
DUSAGE_DIR=/var/lib/sgx-guardian/dusage    # state.json + history.jsonl + quota.json

# Confirm sampler started + dir exists:
grep -a "Data-usage\|dusage" /var/log/sgx-guardian/audit-nodeA.log | tail -1
ls -l "$DUSAGE_DIR"

# Raw kernel counters (ground truth the module reads from):
for i in /sys/class/net/*/statistics; do echo "$i: rx=$(cat $i/rx_bytes) tx=$(cat $i/tx_bytes)"; done

# --- Traffic generator helper (moves the counters) ---
gen_traffic () {  # ~20 MB toward the peer
  dd if=/dev/zero bs=1M count=20 2>/dev/null | nc -w1 192.168.50.248 50063 2>/dev/null || \
  ping -c 200 -s 1400 192.168.50.248 >/dev/null 2>&1 || true
}
```

> **Note:** Ye feature **per-Guardian local** hai (har node apni usage measure karta hai) — cross-node aggregation nahi. Usage **period-relative** hai: raw `/sys` counters cumulative-since-boot hain, module `current − baseline` compute karta hai. Sampler ko **ek sample interval** chahiye naya data reflect karne ke liye.

---

## ⏳ Requirement 1 — [ ] Bandwidth monitoring (per-interface, real, counters move)

> Per-interface rx/tx `/sys/class/net/*/statistics/*` se — real, live, aur **traffic ke saath grow** hota hai (mock nahi). `total_bytes` = Σ interface rx+tx (this period).

**Commands (nodeA):**
```bash
# Baseline reading:
curl -s "$API/dusage/current" | python3 -m json.tool | head -30
B=$(curl -s "$API/dusage/current" | python3 -c "import sys,json;print(json.load(sys.stdin)['total_bytes'])")

# Generate ~20 MB, wait > 1 sample:
gen_traffic
sleep 20

# After — total should have grown:
A=$(curl -s "$API/dusage/current" | python3 -c "import sys,json;print(json.load(sys.stdin)['total_bytes'])")
echo "total BEFORE=$B AFTER=$A  (AFTER must be > BEFORE)"

# Cross-check against raw kernel counter (module must match /sys, not invent numbers):
curl -s "$API/dusage/current" | python3 -c "import sys,json;[print(i['iface'],'rx_total=',i['rx_total']) for i in json.load(sys.stdin)['interfaces']]"
```

**Expected:**
```
current → interfaces[] with real rx/tx (this period) + rx_total/tx_total (raw counters)
After ~20 MB of traffic, total_bytes grows; rx_total matches /sys/class/net/*/statistics
Not representative/mock — numbers track actual kernel counters
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

---

## ⏳ Requirement 2 — [ ] Per-category monitoring (per-port-group via nftables counters) — D5

> D5 me `counter name "<cat>"` enforcement rules pe add hota hai (accept/drop **unchanged**). `nft list counters` per-category bytes deta hai (gossip/registry/cert-bootstrap/nebula...). `/dusage/current` categories[] show karta hai.

**Commands (nodeA):**
```bash
# Named counters declared + accumulating in the ruleset:
nft list counters
# Firewall behaviour unchanged (chain still policy drop, gossip still allowed):
nft list ruleset | grep -E "policy drop|dport 50063"

# Drive gossip traffic then read per-category:
curl -s -X POST "$API/crl/gossip/trigger" >/dev/null
sleep 20
curl -s "$API/dusage/current" | python3 -c "import sys,json;[print(c['category'],c['bytes']) for c in json.load(sys.stdin).get('categories',[])]"
```

**Expected:**
```
nft list counters → gossip/registry/cert-bootstrap/nebula counters present, bytes > 0 after traffic
Chain still 'policy drop' + '50063 accept' — counter is non-behavioural
current.categories[] populated (gossip bytes grew after a gossip round)
```
**Note:** Agar D5 abhi build nahi hua to categories[] empty rahega — that's expected, mark this ⏳ until D5.

**Result:**
```
(paste output)
```

**Verdict:** ⏳

---

## ⏳ Requirement 3 — [ ] Quota tracking + colour thresholds

> `used_pct` = total/quota. Colour bands: **>80% red, >50% amber, else green** (server-side, so har client consistent).

**Commands (nodeA):**
```bash
# No quota → used_pct null / monitor-only:
curl -s -X PUT "$API/dusage/quota" -H 'content-type: application/json' -d '{"quota_bytes":0,"period":"monthly"}' >/dev/null
curl -s "$API/dusage/current" | python3 -c "import sys,json;print('used_pct (no quota):',json.load(sys.stdin).get('used_pct'))"

# Small quota so current usage crosses a threshold:
curl -s -X PUT "$API/dusage/quota" -H 'content-type: application/json' -d '{"quota_bytes":1048576,"period":"monthly"}' | python3 -m json.tool
curl -s "$API/dusage/current" | python3 -c "import sys,json;d=json.load(sys.stdin);p=d.get('used_pct');print('used_pct:',p,'| band:', 'red' if p and p>80 else 'amber' if p and p>50 else 'green')"

# Quota signed on disk:
python3 -c "import json;q=json.load(open('$DUSAGE_DIR/quota.json'));print('quota:',q['quota_bytes'],'has_proof:', 'proof' in q,'seq:',q.get('sequence'))"
```

**Expected:**
```
No quota → used_pct null (monitor-only)
Small quota → used_pct computed; band matches thresholds (>80 red / >50 amber / else green)
quota.json signed (proof present), sequence increments on PUT
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

---

## ⏳ Requirement 4 — [ ] Usage history + analytics (completed periods)

> Har completed period ka snapshot `history.jsonl` (capped ring) mein — analytics/breakdown ke liye. Rollover par current period snapshot hota hai + baselines re-set.

**Commands (nodeA):**
```bash
# Force a quick rollover for testing: set a short period window if supported, else inspect current history.
curl -s "$API/dusage/history" | python3 -c "import sys,json;h=json.load(sys.stdin);print('periods:',len(h));[print(p['period_start'],'total=',p['total_bytes']) for p in h[-3:]]"

# Analytics shape — a completed snapshot carries interface + category breakdown:
curl -s "$API/dusage/history" | python3 -c "import sys,json;h=json.load(sys.stdin);print('sample snapshot keys:', sorted(h[-1].keys()) if h else 'none yet')"
```

**Expected:**
```
history → list of completed-period UsageSnapshots (capped ring)
each snapshot has interfaces[]/categories[]/total_bytes/period_start (breakdown for analytics)
```
**Note:** Agar abhi tak koi period complete nahi hua (fresh install), history empty ho sakti hai — rollover ke baad populate hogi (DUSAGE-005 mein test).

**Result:**
```
(paste output)
```

**Verdict:** ⏳

---

## ⏳ Requirement 5 — [ ] Reset scheduling (period rollover + manual reset)

> (a) **Period rollover** (daily/weekly/monthly) par current period history mein snapshot hota hai aur baselines current raw values pe re-set hote hain. (b) **Manual reset** (`POST /dusage/reset`) current period ko abhi re-baseline karta hai.

**Commands (nodeA):**
```bash
# Manual reset — current period usage goes to ~0, baselines snap to current raw:
BEFORE=$(curl -s "$API/dusage/current" | python3 -c "import sys,json;print(json.load(sys.stdin)['total_bytes'])")
curl -s -X POST "$API/dusage/reset" | python3 -m json.tool
sleep 2
AFTER=$(curl -s "$API/dusage/current" | python3 -c "import sys,json;print(json.load(sys.stdin)['total_bytes'])")
echo "total BEFORE reset=$BEFORE  AFTER reset=$AFTER  (AFTER should be ~0)"

# state.json baselines re-set + period_start updated:
python3 -c "import json;s=json.load(open('$DUSAGE_DIR/state.json'));print('period_start:',s['period_start']);print('iface_baselines:',list(s['iface_baselines'].items())[:3])"

# (Period rollover: set SGX_DUSAGE_PERIOD=daily and cross a day boundary, or use a test hook,
#  then confirm the completed period appears in /dusage/history.)
```

**Expected:**
```
POST /dusage/reset → current period total ~0, baselines re-snapped, period_start updated
Rollover → completed period lands in /dusage/history, new period starts clean
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

---

## ⏳ Requirement 6 — [ ] Cumulative-counter correctness (reboot/reset safe)

> **The key subtlety.** `/sys` counters cumulative + reboot pe zero. Module ko `current < baseline` detect karke **re-baseline** karna chahiye — **kabhi negative ya giant spurious spike report na kare**.

**Commands (nodeA):**
```bash
# Snapshot current usage:
curl -s "$API/dusage/current" | python3 -c "import sys,json;[print(i['iface'],'rx_bytes=',i['rx_bytes']) for i in json.load(sys.stdin)['interfaces']]"

# Simulate a counter reset WITHOUT reboot (flush nft counters if D5), OR actually reboot the board:
#   Option A (D5): nft reset counters
#   Option B: ssh root@192.168.50.115 reboot   # then wait for boot + daemon
sleep 15   # let a sample run after the reset

# After reset — values MUST be non-negative and sane (no 18-exabyte wrap, no negative):
curl -s "$API/dusage/current" | python3 -c "import sys,json;bad=[i for i in json.load(sys.stdin)['interfaces'] if i['rx_bytes']<0 or i['rx_bytes']>10**15];print('sane' if not bad else f'BAD: {bad}')"
grep -a "re-baseline\|counter reset\|dusage.*reset detected" /var/log/sgx-guardian/audit-nodeA.log | tail -2
```

**Expected:**
```
After a counter reset/reboot: rx_bytes/tx_bytes stay non-negative and sane (no spurious spike)
audit shows a re-baseline event (backwards counter detected → baseline reset)
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

---

# 🔌 API Verification — New Endpoints

## ⏳ API 1 — [ ] GET `/api/v1/dusage/current`

**Command:**
```bash
curl -s "$API/dusage/current" | python3 -m json.tool
```

**Expected:**
```json
{
  "period": "monthly",
  "period_start": "2026-07-...",
  "interfaces": [{"iface":"wlan0","rx_bytes":...,"tx_bytes":...,"rx_total":...,"tx_total":...}],
  "categories": [],
  "total_bytes": ...,
  "quota_bytes": ...,
  "used_pct": ...,
  "sampled_at": "2026-07-..."
}
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

## ⏳ API 2 — [ ] GET `/api/v1/dusage/history`

**Command:**
```bash
curl -s "$API/dusage/history" | python3 -c "import sys,json;h=json.load(sys.stdin);print('periods:',len(h))"
```

**Expected:**
```
List of completed-period UsageSnapshots (capped ring); empty until the first rollover
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

## ⏳ API 3 — [ ] GET + PUT `/api/v1/dusage/quota`

**Command:**
```bash
curl -s "$API/dusage/quota" | python3 -m json.tool
curl -s -X PUT "$API/dusage/quota" -H 'content-type: application/json' -d '{"quota_bytes":5368709120,"period":"monthly"}' | python3 -m json.tool
```

**Expected:**
```
GET → {quota_bytes, period, sequence} ; PUT → persisted, signed, sequence incremented
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

## ⏳ API 4 — [ ] POST `/api/v1/dusage/reset`

**Command:**
```bash
curl -s -X POST "$API/dusage/reset" | python3 -m json.tool
curl -s "$API/dusage/current" | python3 -c "import sys,json;print('total after reset:',json.load(sys.stdin)['total_bytes'])"
```

**Expected:**
```
reset → current period re-baselined (total ~0), state.json period_start updated
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

## ⏳ API 5 — [ ] Security — tampered `quota.json` rejected (signature)

> `quota.json` ki value flip karke restart — signed quota invalid ho jaani chahiye, tampered value honor NA ho (fail-closed).

**Command (nodeA):**
```bash
cp "$DUSAGE_DIR/quota.json" /tmp/quota.bak
python3 -c "import json;q=json.load(open('$DUSAGE_DIR/quota.json'));q['quota_bytes']=1;json.dump(q,open('$DUSAGE_DIR/quota.json','w'))"
pkill -f sgx_guardian_client && sleep 3 && ./sgx_guardian_client nodeA & sleep 8
grep -a "quota.*invalid\|quota.*signature\|dusage quota rejected" /var/log/sgx-guardian/audit-nodeA.log | tail -2
curl -s "$API/dusage/quota" | python3 -c "import sys,json;print('quota_bytes:',json.load(sys.stdin)['quota_bytes'])"
# RESTORE:
cp /tmp/quota.bak "$DUSAGE_DIR/quota.json" && pkill -f sgx_guardian_client && sleep 3 && ./sgx_guardian_client nodeA &
```

**Expected:**
```
Tampered quota (quota_bytes=1) NOT honored → fail-closed (defaults / last-good), audit line present
```

**Result:**
```
(paste output)
```

**Verdict:** ⏳

---

## 🗺️ Test-Tag Mapping (DUSAGE-series)

| Tag | What it proves | Section above |
|---|---|---|
| DUSAGE-001 | Bandwidth monitoring (per-interface, real, counters move) | Req 1 |
| DUSAGE-002 | Per-category (per-port-group via nft counters) — D5 | Req 2 |
| DUSAGE-003 | Quota tracking + colour thresholds | Req 3 |
| DUSAGE-004 | Usage history + analytics | Req 4 |
| DUSAGE-005 | Reset scheduling (rollover + manual) | Req 5 |
| DUSAGE-006 | Cumulative-counter correctness (reboot/reset safe) | Req 6 |
| DUSAGE-007 | GET /dusage/current | API 1 |
| DUSAGE-008 | history / quota / reset APIs | API 2 + API 3 + API 4 |
| DUSAGE-009 | Signed-quota tamper rejection (fail-closed) | API 5 |

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
DUSAGE_DIR=/var/lib/sgx-guardian/dusage

# Sampler alive? (startup line)
grep -a "Data-usage\|dusage" /var/log/sgx-guardian/audit-nodeA.log | tail -1

# Raw kernel counters (the source of truth):
for i in /sys/class/net/*/statistics; do echo "$i rx=$(cat $i/rx_bytes) tx=$(cat $i/tx_bytes)"; done
cat /proc/net/dev

# nftables counters (only after D5):
nft list counters 2>/dev/null

# State + quota + history on disk:
cat "$DUSAGE_DIR/state.json" | python3 -m json.tool
cat "$DUSAGE_DIR/quota.json" | python3 -m json.tool
wc -l "$DUSAGE_DIR/history.jsonl" 2>/dev/null

# Enforcement unharmed (esp. after D5 counter edit):
nft list ruleset | grep -E "policy drop|dport 50063"
curl -s "$API/crl/gossip/status" | python3 -c "import sys,json;print(json.load(sys.stdin).get('merkle_root'))"

# Full data-usage trail:
grep -a "Dusage\|dusage\|re-baseline" /var/log/sgx-guardian/audit-nodeA.log | tail -20

# Reset test state (dummy only):
pkill -f sgx_guardian_client
rm -f "$DUSAGE_DIR/state.json" "$DUSAGE_DIR/history.jsonl"   # quota.json preserved
./sgx_guardian_client nodeA

# Isolate a clean test run (empty dir override):
SGX_GUARDIAN_DUSAGE_BASE=/tmp/dusage-test ./sgx_guardian_client nodeA
```

**Timing cheat-sheet:** usage updates on the sampler tick (`SGX_DUSAGE_SAMPLE_SECS`, default 60 — set to 15 for testing) · after generating traffic, wait ≥ one interval before re-reading · history populates only at a **period rollover** (use `SGX_DUSAGE_PERIOD=daily` + a day boundary, or a manual reset, to exercise faster) · `/sys` counters are the ground truth — cross-check the API against them.

---

## 🔗 Cross-feature note

**Correction from grounding:** nftables rules had **no** counters — the core uses `/sys/class/net/*/statistics/*` (zero enforcement change, durable across the planned **eBPF** migration in Sprint 9). Per-category (D5) is the one **additive** enforcement edit (`counter name` — non-behavioural). **Per-device (per-IP)** is the harder conntrack/IP-keyed path (optional D6). The FE's non-network "categories" (AI cache, local telemetry) are **not** network bytes — flag to FE for re-scoping or a separate disk/subsystem source.
