#!/usr/bin/env bash
set -u

BASE="http://localhost:8443/api/v1"

test_api() {
  NAME="$1"
  METHOD="$2"
  URL="$3"
  DATA="${4:-}"

  echo "=============================="
  echo "TEST: $NAME"
  echo "URL:  $URL"

  if [ -z "$DATA" ]; then
    RESP=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X "$METHOD" "$URL")
  else
    RESP=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X "$METHOD" -H "Content-Type: application/json" -d "$DATA" "$URL")
  fi

  CODE=$(echo "$RESP" | tail -n1 | cut -d: -f2)
  BODY=$(echo "$RESP" | sed '$d')

  echo "HTTP: $CODE"
  echo "$BODY"

  if [ "$CODE" = "200" ]; then
    echo "RESULT: API ROUTE WORKING"
  else
    echo "RESULT: NEEDS FIX"
  fi
  echo
}

test_api "DKP Rotate" "POST" "$BASE/dkp/rotate"
test_api "DKP Revoke" "POST" "$BASE/dkp/revoke" '{"version":1,"reason":"test revoke"}'
test_api "Emergency Rotate" "POST" "$BASE/dkp/emergency-rotate" '{}'
test_api "PCR Baseline Create" "POST" "$BASE/pcr/baseline/create"
test_api "PCR Baseline Verify" "POST" "$BASE/pcr/baseline/verify"

echo "=============================="
echo "TEST: Policy Sign"
curl -s -i -X POST \
  -F "policy=@/home/asad/SGX/policies/active_policy.yaml" \
  -F "key=@/home/asad/SGX/sgx-pa-cli/guardian_private.key" \
  "$BASE/policy/sign"
echo

echo "=============================="
echo "TEST: Policy Verify"
curl -s -i -X POST \
  -F "policy=@/home/asad/SGX/sgx-pa-cli/policy.sig" \
  "$BASE/policy/verify"
echo
