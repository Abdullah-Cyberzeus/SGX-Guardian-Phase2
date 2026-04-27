#!/usr/bin/env bash
set -euo pipefail

NODE="${1:-nodeA}"
LOG_DIR="${2:-./logs}"
LOG_FILE="${LOG_DIR}/cot_${NODE}_$(date +%Y%m%d_%H%M%S).log"

mkdir -p "${LOG_DIR}"

echo "[1/4] Starting ${NODE} with CoT hotplug/link/failover stack"
echo "Log: ${LOG_FILE}"

sudo env "PATH=$PATH" "HOME=$HOME" cargo run -- "${NODE}" | tee "${LOG_FILE}"

echo "[2/4] Expected startup checks:"
echo "  - Transport summary contains interface names, e.g. ens33 + ens37"
echo "  - No false 'appeared' message for baseline interfaces"

echo "[3/4] Manual VMware actions:"
echo "  - Disconnect Adapter 2 (ens37) and verify no 'All transports down'"
echo "  - Disconnect Adapter 1 (ens33) and observe failover"
echo "  - Reconnect ens33 and observe upgrade"

echo "[4/4] Quick grep helpers:"
echo "  grep -n 'Transport Registry' '${LOG_FILE}'"
echo "  grep -n 'Hotplug: interface .* appeared' '${LOG_FILE}'"
echo "  grep -n 'All transports down' '${LOG_FILE}'"
echo "  grep -n 'Failover:' '${LOG_FILE}'"
echo "  grep -n 'Upgrade:' '${LOG_FILE}'"
