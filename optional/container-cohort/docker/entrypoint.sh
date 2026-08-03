#!/bin/sh
# SG-X Guardian container entrypoint.
# Node selection precedence: $NODE_ID env > first argv > baked CMD default.
set -eu

NODE="${NODE_ID:-${1:-nodeA}}"

echo "-- SG-X Guardian container --------------------------------"
echo "   node_id            : ${NODE}"
echo "   nebula gate        : SGX_DISABLE_NEBULA=${SGX_DISABLE_NEBULA:-<unset>}"
echo "   enforcement gate   : SGX_DISABLE_POLICY_ENFORCEMENT=${SGX_DISABLE_POLICY_ENFORCEMENT:-<unset>}"
echo "   platform mode      : SGX_PLATFORM_MODE=${SGX_PLATFORM_MODE:-auto}"
if [ -n "${SGX_SOFTHSM_PIN:-}" ]; then
  echo "   softhsm pin        : set"
else
  echo "   softhsm pin        : missing"
fi
echo "   lighthouse ip      : SGX_LIGHTHOUSE_IP=${SGX_LIGHTHOUSE_IP:-<unset>}"
echo "-----------------------------------------------------------"

exec /usr/local/bin/sgx_guardian_client "${NODE}"
