#!/bin/sh
# SG-X Guardian container entrypoint.
# Node selection precedence: $NODE_ID env > first argv > baked CMD default.
set -eu

NODE="${NODE_ID:-${1:-nodeA}}"

echo "-- SG-X Guardian container --------------------------------"
echo "   node_id            : ${NODE}"
echo "   nebula gate        : SGX_DISABLE_NEBULA=${SGX_DISABLE_NEBULA:-<unset>}"
echo "   enforcement gate   : SGX_DISABLE_POLICY_ENFORCEMENT=${SGX_DISABLE_POLICY_ENFORCEMENT:-<unset>}"
echo "   software keys      : SGX_FORCE_SOFTWARE_KEYS=${SGX_FORCE_SOFTWARE_KEYS:-<unset>}"
echo "   lighthouse ip      : SGX_LIGHTHOUSE_IP=${SGX_LIGHTHOUSE_IP:-<unset>}"
echo "-----------------------------------------------------------"

if [ "${NODE}" = "broker" ] || [ "${1:-}" = "broker" ]; then
    echo "   mode               : SGX Cloud Enrollment Broker (VPS)"
    echo "-----------------------------------------------------------"
    exec /usr/local/bin/sgx-broker
fi

exec /usr/local/bin/sgx_guardian_client "${NODE}"
