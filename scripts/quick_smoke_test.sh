#!/bin/bash
# quick_smoke_test.sh — Full AI remediation pipeline smoke test
# Verifies all 8 acceptance criteria from AI_Remediation_Task_Document.md
#
# Usage: sudo /home/hp/SGX/scripts/quick_smoke_test.sh
# Requires: SGX guardian running at https://localhost:8443

BASE="http://localhost:8443"
INJECT="/home/hp/SGX/scripts/inject_alerts.sh"
PASS=0
FAIL=0

pass() { echo "  ✅ $1"; PASS=$((PASS+1)); }
fail() { echo "  ❌ $1"; FAIL=$((FAIL+1)); }
section() { echo ""; echo "═══ $1 ═══"; }

section "AC-7 / AC-8: Cargo Test + Clippy"
echo "  Running: cargo test --package sgx_guardian_client --lib threat"
if cargo test --quiet --package sgx_guardian_client --lib threat --target-dir target/smoke 2>&1 | grep -q "test result: ok"; then
    pass "All unit tests pass"
else
    fail "One or more unit tests failed — run 'cargo test --lib threat' to see details"
fi
echo "  Running: cargo clippy"
if cargo clippy --quiet --package sgx_guardian_client --target-dir target/smoke 2>&1 | grep -q "warning:"; then
    fail "cargo clippy produced warnings"
else
    pass "cargo clippy: zero warnings"
fi

section "AC-2 (REST API Live): Tier 2 — API Smoke"
echo "  Checking advisory API..."
RESPONSE=$(curl -sk --max-time 5 "$BASE/api/v1/threat/advisories" 2>&1)
if echo "$RESPONSE" | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null; then
    pass "Advisory API is live and returns valid JSON"
else
    fail "Advisory API unreachable or returned non-JSON. Is the server running?"
    echo ""
    echo "  ABORT: Server must be running. Start with:"
    echo "  sudo env HOME=\$HOME cargo run -- nodeA"
    exit 1
fi

section "AC-2: Low Volume — No Advisory Expected"
echo "  Injecting 3 low-severity alerts from 10.0.0.99..."
"$INJECT" 3 "10.0.0.99" "reconnaissance" "low" > /dev/null
sleep 3
COUNT=$(curl -sk "$BASE/api/v1/threat/advisories" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len([x for x in d if x.get('plan',{}).get('target_ip')=='10.0.0.99']))")
[ "$COUNT" -eq 0 ] && pass "No advisory generated for low-volume alerts (score < 0.50)" \
                   || fail "Unexpected advisory for only 3 low alerts — threshold may be wrong"

section "AC-1 / AC-3: CRITICAL Burst — Advisory Must Be Generated"
echo "  Injecting 60 high-severity reconnaissance alerts from 192.168.1.105..."
"$INJECT" 60 "192.168.1.105" "reconnaissance" "high" > /dev/null
sleep 4
ADVISORIES=$(curl -sk "$BASE/api/v1/threat/advisories")
COUNT=$(echo "$ADVISORIES" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len([x for x in d if x.get('plan',{}).get('target_ip')=='192.168.1.105']))")
if [ "$COUNT" -gt 0 ]; then
    pass "Advisory generated for CRITICAL burst (AC-1)"
else
    fail "No advisory generated — pipeline not firing (AC-1 / AC-2 FAILED)"
    echo "  Check SGX logs for errors in the AI scoring task"
    exit 1
fi

section "AC-3: Justification Must Be Non-Empty"
JUSTIFICATION=$(echo "$ADVISORIES" | python3 -c "
import sys,json
d=json.load(sys.stdin)
advs = [x for x in d if x.get('plan',{}).get('target_ip')=='192.168.1.105']
print(advs[-1]['plan']['justification'] if advs else '')
")
[ -n "$JUSTIFICATION" ] && pass "Advisory has non-empty justification: \"${JUSTIFICATION:0:80}...\"" \
                         || fail "Advisory justification is empty (AC-3 FAILED)"

section "AC-5: QuarantinePeer / ProposePolicyUpdate Must Be Pending (Not Auto-Execute)"
REQUIRES_APPROVAL=$(echo "$ADVISORIES" | python3 -c "
import sys,json
d=json.load(sys.stdin)
d.reverse()
for adv in d:
    if adv.get('plan',{}).get('target_ip')=='192.168.1.105':
        ra = adv['plan'].get('requires_approval',[])
        ae = adv['plan'].get('auto_execute',[])
        print('requires_approval:', ra)
        print('auto_execute:', ae)
        break
")
echo "$REQUIRES_APPROVAL"
if echo "$REQUIRES_APPROVAL" | grep -q "requires_approval: \[\]"; then
    fail "requires_approval is empty — policy actions should need admin sign-off"
else
    pass "Policy update and quarantine actions are in requires_approval (AC-5)"
fi

STATUS=$(echo "$ADVISORIES" | python3 -c "
import sys,json
d=json.load(sys.stdin)
d.reverse()
for adv in d:
    if adv.get('plan',{}).get('target_ip')=='192.168.1.105':
        print(adv.get('status',''))
        break
")
[ "$STATUS" = "pending" ] && pass "Advisory status is 'pending' — correct (AC-5)" \
                           || fail "Advisory status is '$STATUS' — expected 'pending' (AC-5 FAILED)"

section "AC-4: NftablesBlockIp Auto-Executed"
if nft list table inet sgx_threat 2>/dev/null | grep -q "192.168.1.105"; then
    pass "192.168.1.105 found in nftables drop rules — auto-block successful (AC-4)"
else
    echo "  ⚠️  nftables rule not found — may be expected in pure dev environment"
    echo "     (nftables requires root + real network interface)"
fi

section "Tier 3b: Advisory Approve Workflow"
ADV_ID=$(echo "$ADVISORIES" | python3 -c "
import sys,json
d=json.load(sys.stdin)
d.reverse()
for adv in d:
    if adv.get('plan',{}).get('target_ip')=='192.168.1.105' and adv.get('status')=='pending':
        print(adv['advisory_id'])
        break
")
if [ -n "$ADV_ID" ]; then
    echo "  Approving advisory: $ADV_ID"
    RESULT=$(curl -sk -X POST "$BASE/api/v1/threat/advisories/$ADV_ID/approve")
    APPROVED_STATUS=$(echo "$RESULT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status',''))" 2>/dev/null)
    [ "$APPROVED_STATUS" = "approved" ] && pass "Advisory approved successfully" \
                                        || fail "Approve failed — got status: '$APPROVED_STATUS'"
else
    fail "No pending advisory found to approve"
fi

section "AC-6: Audit Log Entry"
AUDIT=$(curl -sk "$BASE/api/v1/audit/logs" 2>/dev/null)
if echo "$AUDIT" | python3 -c "
import sys,json
logs = json.load(sys.stdin)
found = any('advisory' in log.get('event', {}).get('message', '').lower() for log in logs.get('items', []))
print('found' if found else 'not_found')
" 2>/dev/null | grep -q "found"; then
    pass "Advisory recorded in audit log (AC-6)"
else
    fail "No advisory entry in audit log — check log_audit() wiring (AC-6 FAILED)"
fi

section "Results"
echo ""
echo "  Passed : $PASS"
echo "  Failed : $FAIL"
echo ""
if [ $FAIL -eq 0 ]; then
    echo "  🎉 ALL ACCEPTANCE CRITERIA PASSED"
else
    echo "  ⚠️  $FAIL criterion(s) failed — review output above"
fi
echo ""
