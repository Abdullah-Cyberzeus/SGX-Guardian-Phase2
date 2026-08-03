# SGX Guardian — Board AI Security System Testing Guide

**Target Hardware:** Variscite i.MX8M Plus (`imx8mp-var-dart`)
**Purpose:** Step-by-step verification that all AI Threat Remediation components are fully operational on real hardware.

> **Environment:**
> - Board IP: `192.168.1.195` (nodeA)
> - Attacker/Test IP: `192.168.1.188` (test laptop)
> - SGX API: `http://127.0.0.1:8443/api/v1`
> - Auth: `SGX_DISABLE_LOGIN=1` (dev mode) or Bearer token in production

---

## Prerequisites

```bash
# 1. Start SGX Guardian (on the board)
SGX_DISABLE_LOGIN=1 ./sgx_guardian_client nodeA

# 2. Verify API is responding
curl -s "http://127.0.0.1:8443/api/v1/health"
# Expected: {"status":"ok"}

# 3. Verify Suricata is running
sudo systemctl status suricata
sudo tail -n 5 /var/log/suricata/suricata.log | grep "engine started"
```

---

## Clean Slate Reset

Run before each test to wipe all previous state:

```bash
sudo truncate -s 0 /var/log/suricata/eve.json
sudo nft flush table inet sgx_threat 2>/dev/null; true
sudo rm -f /var/lib/sgx-guardian/threat/blocked_ips.json
# Then restart sgx_guardian_client to clear in-memory advisories
```

---

## Test 1 — Baseline Filter (No Advisory)

**Goal:** 3 low-severity alerts must NOT generate an advisory.

```bash
sudo ./scripts/inject_alerts.sh 3 "10.0.0.99" "reconnaissance" "low"
sleep 4
curl -s "http://127.0.0.1:8443/api/v1/threat/advisories" | python3 -m json.tool
```

**Expected:** `[]`

---

## Test 2 — Critical Burst Detection

**Goal:** 15 high-severity alerts trigger an advisory with appropriate remediation recommendations.

```bash
sudo ./scripts/inject_alerts.sh 15 "192.168.1.188" "reconnaissance" "high"
sleep 4
```

**Step A — Advisory created:**
```bash
curl -s "http://127.0.0.1:8443/api/v1/threat/advisories" | python3 -m json.tool
```
Expected: `severity_label: critical/elevated`, `auto_execute` contains `alert_only`, and `requires_approval` contains mitigation actions.

**Step B — Audit log entry:**
```bash
grep "192.168.1.188" /var/log/sgx-guardian/audit-nodeA.log | tail -n 3
```
Expected: `"action":"Detected"` and `"action":"Created"` with `security advisory adv-XXXX generated`

---

## Test 3 — Approve a Pending Advisory

**Goal:** Human admin approves an AI recommendation via REST API.

```bash
ADV_ID=$(curl -s "http://127.0.0.1:8443/api/v1/threat/advisories?status=pending" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d[0]['advisory_id']) if d else print('NONE')")
echo "Approving: $ADV_ID"

curl -s -X POST "http://127.0.0.1:8443/api/v1/threat/advisories/$ADV_ID/approve" \
  | python3 -m json.tool
```

**Expected:** `"status": "approved"`, `"resolved_at"` is non-null

---

## Test 4 — Reject Advisory (Idempotency)

**Goal:** Admin rejects an advisory. Rejected advisories cannot be re-approved.

```bash
sudo ./scripts/inject_alerts.sh 15 "10.99.0.1" "exploit" "high"
sleep 4

ADV_ID=$(curl -s "http://127.0.0.1:8443/api/v1/threat/advisories?status=pending" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d[0]['advisory_id']) if d else print('NONE')")

# Reject
curl -s -X POST "http://127.0.0.1:8443/api/v1/threat/advisories/$ADV_ID/reject" \
  | python3 -m json.tool

# Try to approve the rejected advisory (must fail)
curl -s -X POST "http://127.0.0.1:8443/api/v1/threat/advisories/$ADV_ID/approve" \
  | python3 -m json.tool
```

**Expected:**
- First call: `"status": "rejected"`
- Second call: `{"error":{"code":"NOT_FOUND",...}}`

---

## Test 5 — Malware Tiered Response

**Goal:** Malware category produces an advisory with specific remediation recommendations.

```bash
sudo ./scripts/inject_alerts.sh 15 "10.0.77.1" "malware" "high"
sleep 4
curl -s "http://127.0.0.1:8443/api/v1/threat/advisories?status=pending" | python3 -m json.tool
```

**Expected:**
- `auto_execute`: `alert_only`
- `requires_approval`: Contains `nftables_block_ip` AND `quarantine_peer`

---

## Test 6 — Policy Violation (Advisory Only)

**Goal:** Ensure policy violations generate advisories but do not automatically execute blocking rules (Advisory-Only posture).

```bash
sudo ./scripts/inject_alerts.sh 15 "172.16.0.8" "policy-violation" "medium"
sleep 4

# Check advisory actions
curl -s "http://127.0.0.1:8443/api/v1/threat/advisories" | python3 -c "
import sys, json
for adv in json.load(sys.stdin):
    if '172.16.0.8' in adv['plan']['target_ip']:
        print('Auto-execute:', adv['plan']['auto_execute'])
"
```

**Expected:** Auto-execute contains only `alert_only`.

---

## Test 7 — Audit Log Hash Chain Integrity

**Goal:** Verify cryptographic tamper-evidence. Each entry's `hash` must equal the next entry's `previous_hash`.

```bash
tail -n 2 /var/log/sgx-guardian/audit-nodeA.log | python3 -c "
import sys, json
lines = [json.loads(l) for l in sys.stdin if l.strip()]
if len(lines) >= 2:
    prev, curr = lines[0], lines[1]
    print('Previous hash :', prev['hash'])
    print('previous_hash :', curr['previous_hash'])
    print('Integrity     :', 'VALID' if prev['hash'] == curr['previous_hash'] else 'BROKEN')
"
```

**Expected:**
```
Previous hash : <value>
previous_hash : <same value>
Integrity     : VALID
```

---

## Test 8 — Real Hardware: Attestation Mismatch Anomaly

**Goal:** Verify that a real hardware PCR/attestation mismatch anomaly generates recommendations to tighten attestation interval (15s) and quarantine the peer.

### Trigger Mechanism
This is a real internal hook. It is triggered automatically when a peer node presents a valid TPM quote, but the PCR composite digest does not match the baseline stored in `attestation_service.rs`. 
*(Note: For simulated testing without hardware failure, the `inject_alerts.sh` script can still spoof this category).*

### Verify
```bash
curl -s "http://127.0.0.1:8443/api/v1/threat/advisories" | python3 -c "
import sys, json
for adv in json.load(sys.stdin):
    if 'attestation_peer' in adv['plan']['target_ip']:
        print('Category         :', adv['plan']['score']['category'])
        print('Requires Approval:', adv['plan']['requires_approval'])
"
```

**Expected:** Category `attestation_mismatch` with recommendations `tighten_attestation` and `quarantine_peer`.

---

## Test 9 — Real Hardware: Certificate Issue Anomaly

**Goal:** Verify that a real PKI/certificate anomaly generates a recommendation to propose cert renewal/rotation policy update.

### Trigger Mechanism
This is a real internal hook. It is triggered automatically by the `ExpiryMonitor` in `cert_lifecycle.rs` when the local node's Nebula certificate expires or reaches critical expiration (<= 7 days).
*(Note: For simulated testing, the `inject_alerts.sh` script can still spoof this category).*

### Verify
```bash
curl -s "http://127.0.0.1:8443/api/v1/threat/advisories" | python3 -c "
import sys, json
for adv in json.load(sys.stdin):
    if '127.0.0.1' in adv['plan']['target_ip']:
        print('Category         :', adv['plan']['score']['category'])
        print('Requires Approval:', adv['plan']['requires_approval'])
"
```

**Expected:** Category `certificate_issue` with recommendation `propose_policy_update` (`renew_or_rotate_cert`).

---

## Quick Status Checklist

Run at any time for a full system snapshot:

```bash
echo "=== Advisories ===" && \
curl -s "http://127.0.0.1:8443/api/v1/threat/advisories" | python3 -c "
import sys, json
ads = json.load(sys.stdin)
print(f'Total: {len(ads)}')
for a in ads[-3:]:
    print(f'  {a[\"advisory_id\"]} | {a[\"severity_label\"]:10} | {a[\"status\"]:15} | {a[\"plan\"][\"target_ip\"]}')
" && \
echo "" && echo "=== Firewall Blocks ===" && \
sudo nft list table inet sgx_threat 2>/dev/null | grep "saddr" || echo "  None active" && \
echo "" && echo "=== Last Audit Entry ===" && \
tail -n 1 /var/log/sgx-guardian/audit-nodeA.log | python3 -c "
import sys, json
e = json.load(sys.stdin)['event']
print(f'  [{e[\"action\"]}] {e[\"message\"][:100]}')
"
```

---

## Test Results Matrix

| # | Test | Pass Condition |
|:-:|:-----|:--------------|
| 1 | Baseline filter | `[]` — no advisory |
| 2A | Advisory created | `severity_label` present, `auto_execute` is `alert_only` |
| 2B | Audit log entry | `"action":"Created"` present |
| 3 | Advisory approval | `"status":"approved"` |
| 4 | Advisory rejection + idempotency | `"status":"rejected"` + 404 on re-approve |
| 5 | Malware tiered response | `nftables_block_ip` and `quarantine_peer` in requires_approval |
| 6 | Policy violation | `auto_execute` is `alert_only` |
| 7 | Hash chain integrity | `previous_hash` matches preceding `hash` |
| 8 | Attestation Mismatch Hardware Hook | `tighten_attestation` (15s) + `quarantine_peer` |
| 9 | Certificate Issue Hardware Hook | `propose_policy_update` (`renew_or_rotate_cert`) |

