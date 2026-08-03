# Testing Plan: AI-Generated Remediation Recommendations

**Project**: SG-X Guardian (SGX) — Phase 2 Intelligence Layer  
**Document Purpose**: Real-world testing guide for alert scoring, remediation generation, and advisory API  
**Server Port**: `http://localhost:8443` (from your current run)

---

## Overview: 4 Testing Tiers

```
Tier 1 — Automated Unit Tests      (cargo test)            ← Already passing
Tier 2 — REST API Smoke Tests      (curl)                  ← API is live, run now
Tier 3 — Simulated Alert Injection (EVE JSON mock file)    ← Mock Suricata
Tier 4 — Full End-to-End Live      (real Suricata alerts)  ← When Suricata is running
```

---

## Tier 1 — Automated Unit Tests (Already Passing)

Run the full suite any time you change the threat module:

```bash
# Run ALL threat module unit tests (covers alert_scorer, remediation, advisory)
cargo test --package sgx_guardian_client --lib threat

# Run only the specific new modules
cargo test --package sgx_guardian_client --lib threat::alert_scorer
cargo test --package sgx_guardian_client --lib threat::remediation
cargo test --package sgx_guardian_client --lib threat::advisory

# Run with clippy (zero warnings policy)
cargo clippy --package sgx_guardian_client
```

**Expected result**: All tests pass, zero clippy warnings.

---

## Tier 2 — REST API Smoke Tests

Your server is running at `http://localhost:8443`.

### 2.1 Verify Advisory API is Live

```bash
# Should return [] (empty array — no alerts yet)
curl -X GET "http://localhost:8443/api/v1/threat/advisories" | python3 -m json.tool
```

**Expected**: `[]`

### 2.2 Verify Status Filter Works

```bash
# Filter by each status — all should return []
curl -s "http://localhost:8443/api/v1/threat/advisories?status=pending"
curl -s "http://localhost:8443/api/v1/threat/advisories?status=approved"
curl -s "http://localhost:8443/api/v1/threat/advisories?status=auto_executed"
curl -s "http://localhost:8443/api/v1/threat/advisories?status=rejected"
```

### 2.3 Verify 404 for Missing Advisory

```bash
curl -s "http://localhost:8443/api/v1/threat/advisories/adv-nonexistent"
```

**Expected**: 404 response with error message.

---

## Tier 3 — Simulated Alert Injection (Mock Suricata)

This is the most important tier. Since you don't have live Suricata running,
we **simulate it** by writing mock EVE JSON directly to the path SGX watches
(`/var/log/suricata/eve.json`), which causes the `EveTailer` to pick up alerts,
push them through `ai_bridge`, and trigger the entire AI pipeline.

### Step 1: Create the EVE Log File

```bash
sudo mkdir -p /var/log/suricata
sudo touch /var/log/suricata/eve.json
sudo chmod 644 /var/log/suricata/eve.json
```

### Step 2: Use the Alert Injector Script

The script `scripts/inject_alerts.sh` is already in your repo (created alongside this plan).

```bash
# Usage: sudo ./scripts/inject_alerts.sh [count] [src_ip] [category] [severity]

# Quick test — 10 alerts:
sudo /home/hp/SGX/scripts/inject_alerts.sh 10 "192.168.1.105" "reconnaissance" "high"
```

### Scenario A — Low Volume (Should NOT trigger advisory)

```bash
# 3 alerts — should be below 0.50 threshold
sudo /home/hp/SGX/scripts/inject_alerts.sh 3 "10.0.0.5" "reconnaissance" "low"
sleep 2

# Advisory store should still be empty
curl -X GET "http://localhost:8443/api/v1/threat/advisories"
```

**Expected**: `[]` — score < 0.50, no advisory generated.

### Scenario B — CRITICAL Burst (Triggers advisory + auto-block)

```bash
# 60 high-severity reconnaissance alerts from same IP — score >= 0.90
sudo /home/hp/SGX/scripts/inject_alerts.sh 60 "192.168.1.105" "reconnaissance" "high"
sleep 4

curl -X GET "http://localhost:8443/api/v1/threat/advisories" | python3 -m json.tool
```

**Expected output** (abridged):
```json
[
  {
    "advisory_id": "adv-XXXXXXXX",
    "title": "[CRITICAL] RECONNAISSANCE Threat from 192.168.1.105 (Score: 0.9X)",
    "severity_label": "critical",
    "status": "pending",
    "plan": {
      "target_ip": "192.168.1.105",
      "auto_execute": [{"NftablesBlockIp": {"duration_secs": 3600}}],
      "requires_approval": [
        {"ProposePolicyUpdate": {"rule_delta": "deny ip saddr 192.168.1.105 drop;"}},
        {"TightenAttestation": {"interval_secs": 30}}
      ],
      "justification": "Source IP 192.168.1.105 triggered 60 alerts..."
    }
  }
]
```

### Scenario C — Verify Auto-Block in nftables

```bash
# After Scenario B, check if IP was blocked automatically
sudo nft list table inet sgx_threat 2>/dev/null | grep "192.168.1.105"
```

**Expected**: A `drop` rule for `192.168.1.105` (confirms auto-block fired).

### Scenario D — Exploit Category

```bash
# 40 exploit-category alerts — produces 24h block + QuarantinePeer requiring approval
sudo /home/hp/SGX/scripts/inject_alerts.sh 40 "10.99.0.1" "exploit" "high"
sleep 3

curl -s "http://localhost:8443/api/v1/threat/advisories?status=pending" | python3 -m json.tool
```

**Verify**: `quarantine_peer` must be in `requires_approval`, NOT `auto_execute`.

### Scenario E — Malware Category

```bash
sudo /home/hp/SGX/scripts/inject_alerts.sh 45 "10.0.77.1" "malware" "high"
sleep 3

curl -X GET "http://localhost:8443/api/v1/threat/advisories" | python3 -m json.tool
```

**Verify**: Advisory shows `NftablesBlockIp` AND `QuarantinePeer` in requires_approval.

### Scenario F — Policy Violation (Elevated, not Critical)

```bash
sudo /home/hp/SGX/scripts/inject_alerts.sh 20 "172.16.0.8" "policy-violation" "medium"
sleep 3

curl -X GET "http://localhost:8443/api/v1/threat/advisories" | python3 -m json.tool
```

**Verify**: Advisory title starts with `[ELEVATED]`, not `[CRITICAL]`.

---

## Tier 3b — Test the Advisory Approval Workflow

After generating a CRITICAL advisory (Scenario B):

### Approve an Advisory

```bash
# Get the advisory ID from the list
ADV_ID=$(curl -s "http://localhost:8443/api/v1/threat/advisories?status=pending" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d[0]['advisory_id']) if d else print('')")
echo "Advisory ID: $ADV_ID"

# Approve it
curl -s -X POST "http://localhost:8443/api/v1/threat/advisories/adv-da590d0e/approve" \
  | python3 -m json.tool
```

**Expected**: `"status": "approved"` and non-null `resolved_at`.

### Reject a Different Advisory

```bash
# Generate a new one
sudo /home/hp/SGX/scripts/inject_alerts.sh 60 "10.0.99.1" "malware" "high"
sleep 3

# Get pending ID
ADV_ID2=$(curl -s "http://localhost:8443/api/v1/threat/advisories?status=pending" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d[0]['advisory_id']) if d else print('')")

# Reject it
curl -s -X POST "http://localhost:8443/api/v1/threat/advisories/$ADV_ID2/reject" \
  | python3 -m json.tool
```

**Expected**: `"status": "rejected"` with `resolved_at` timestamp set.

### Verify Idempotency (Cannot approve twice)

```bash
# Attempt to approve an already-rejected advisory — should return error
curl -s -X POST "http://localhost:8443/api/v1/threat/advisories/$ADV_ID2/approve"
```

**Expected**: Error response indicating advisory is already resolved.

---

## Tier 3c — Verify Audit Log

Every advisory is written to the SGX tamper-evident audit log. Verify it:

```bash
# Check the SGX audit log for advisory entries
curl -s "http://localhost:8443/api/v1/audit/logs" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for item in data.get('items', []):
    msg = item.get('event', {}).get('message', '')
    if 'advisory' in msg.lower():
        print(json.dumps(item, indent=2))
"
```

**Expected**: Log entries with:
- `category: "network"`
- `action: "created"`
- `message` containing `"security advisory adv-XXXX generated: [CRITICAL]..."`

---

## Tier 4 — Full End-to-End Live Test (Real Suricata)

When Suricata is installed and running on the system:

### Install and Configure Suricata

```bash
sudo apt-get install suricata -y

# Update community IDS rules
sudo suricata-update

# Start Suricata in IDS mode on your primary interface
sudo suricata -c /etc/suricata/suricata.yaml -i eth0 -D

# Verify EVE log is being written
sudo tail -f /var/log/suricata/eve.json
```

### Trigger Real Suricata Alerts via nmap

```bash
# Install nmap
sudo apt-get install nmap -y

# Scan your own node (triggers ET SCAN signatures in Suricata rules)
# WARNING: Only run on your own systems
nmap -sV -p 1-10000 127.0.0.1
```

### Watch the Pipeline in Real Time (3 Terminals)

```bash
# Terminal 1: Watch EVE log for new alerts
sudo tail -f /var/log/suricata/eve.json | grep '"event_type":"alert"'

# Terminal 2: Watch SGX logs for advisory generation
cargo run -- nodeA 2>&1 | grep -i "advisory\|score\|block"

# Terminal 3: Poll advisory API every 2 seconds
watch -n 2 'curl -s "http://localhost:8443/api/v1/threat/advisories" | python3 -m json.tool'
```

### Expected Live Flow

1. `nmap` scan runs → Suricata fires alerts → EVE JSON updated
2. SGX logs show: `"security advisory adv-XXXX generated: [CRITICAL]..."`
3. `curl .../advisories` returns non-empty array with CRITICAL advisory
4. `sudo nft list table inet sgx_threat` shows IP blocked
5. `curl .../audit/logs` shows tamper-evident audit entry

---

## Test Verification Matrix

| # | Acceptance Criterion | Test Tier | How to Verify |
| :--- | :--- | :--- | :--- |
| AC-1 | Score >= 0.90 when 500+ same-SID alerts from single IP in 5 min | Tier 1 unit test | `cargo test` passes `test_burst_alerts_critical_score` |
| AC-2 | `RemediationPlan` produced for every score >= 0.50 | Tier 1 + Tier 3 Scenario A/B | Unit tests + no advisory for 3 alerts, advisory for 60 |
| AC-3 | `SecurityAdvisory` has non-empty `justification` | Tier 3 Scenario B | `plan.justification` field is populated in API response |
| AC-4 | `blocker.rs` called automatically at score >= 0.90 | Tier 3 Scenario C | `sudo nft list table inet sgx_threat` shows drop rule |
| AC-5 | `ProposePolicyUpdate` + `QuarantinePeer` stay `Pending` | Tier 3 Scenario D | These actions only appear in `requires_approval`, never `auto_execute` |
| AC-6 | Every advisory recorded in audit log | Tier 3c | `curl .../audit/logs` shows advisory entry with category=network |
| AC-7 | All existing unit tests continue to pass | Tier 1 | `cargo test --lib threat` → all passed, 0 failed |
| AC-8 | `cargo clippy` zero warnings | Tier 1 | `cargo clippy` → `Finished` with no warnings |

---

## Quick Smoke Test Script

Run `sudo /home/hp/SGX/scripts/quick_smoke_test.sh` to automate steps 2.1, 3A, and 3B.

---

## Troubleshooting

| Symptom | Cause | Fix |
| :--- | :--- | :--- |
| Advisory store always empty after injection | EVE tailer not watching the file / threat service disabled | Ensure `enabled: true` in threat config; check SGX startup logs |
| `nft list` fails | nftables not installed | `sudo apt-get install nftables` |
| `curl` returns SSL error | Dev cert not trusted | Add `-k` flag to all curl commands |
| Score not reaching 0.90 with 60 alerts | Alert count spread across too many IPs | Ensure all injected alerts use the same `src_ip` |
| EVE JSON not being picked up by SGX | Wrong `eve_path` in threat config | Check `eve_path` in `/etc/sgx-guardian/threat/config.yaml` |
| `Permission denied` writing EVE log | sudo needed | Prefix inject script with `sudo` |
