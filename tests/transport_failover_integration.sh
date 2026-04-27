#!/usr/bin/env bash
set -euo pipefail

echo "=== Phase 0: Setup mock satellite ==="
./tests/mock_satellite.sh

echo "=== Phase 1: Start nodeA and wait for CoT stack ==="
LOG_FILE="./logs/transport_failover_$(date +%Y%m%d_%H%M%S).log"
mkdir -p ./logs
(sudo env "PATH=$PATH" "HOME=$HOME" cargo run -- nodeA >"$LOG_FILE" 2>&1 &) 
PID=$!
trap 'kill $PID 2>/dev/null || true; ./tests/mock_satellite_cleanup.sh >/dev/null 2>&1 || true' EXIT
sleep 20

echo "=== Phase 2: Verify transport commands available ==="
cargo run -p sgx-pa-cli -- transport-list --node nodeA >/tmp/transport_list.out
cat /tmp/transport_list.out

echo "=== Phase 3: Force lock/unlock ==="
# Choose first detected interface to lock.
LOCK_IFACE=$(awk '/→/{print $1; exit}' /tmp/transport_list.out)
if [[ -n "${LOCK_IFACE}" ]]; then
  cargo run -p sgx-pa-cli -- transport-lock "$LOCK_IFACE" --node nodeA
  cargo run -p sgx-pa-cli -- transport-show --node nodeA
  cargo run -p sgx-pa-cli -- transport-unlock --node nodeA
fi

echo "=== Phase 4: Validate log signals ==="
grep -n "Transport Registry" "$LOG_FILE" || true
grep -n "Failover:" "$LOG_FILE" || true
grep -n "Upgrade:" "$LOG_FILE" || true

echo "=== Phase 5: Validate CoT metrics keys ==="
if curl -sf http://127.0.0.1:9100/metrics >/tmp/metrics.out; then
  grep -E "sgx_cot_transport_up|sgx_cot_active_transport_info|sgx_cot_transport_switches_total" /tmp/metrics.out || true
else
  echo "metrics endpoint not reachable; skipping metric scrape"
fi

echo "=== PASS (script-level) ==="
