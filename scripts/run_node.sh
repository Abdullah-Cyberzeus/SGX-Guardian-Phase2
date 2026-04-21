#!/bin/sh
NODE_ID="${1:-nodeA}"
LOG="/tmp/sgx_${NODE_ID}.log"

# Kill any existing daemon
pkill -f sgx_guardian_client 2>/dev/null
sleep 2

# Start daemon with output redirected (NEVER on serial console)
/root/sgx_guardian_client "$NODE_ID" > "$LOG" 2>&1 &
PID=$!

echo "Started $NODE_ID (PID $PID)"
echo "Log: $LOG"
echo ""
echo "Watchdog: /root/sgx-watchdog.sh $NODE_ID"
echo "  Heartbeat: /tmp/sgx_guardian_heartbeat"
echo "  Max stale: 600s (10 min)"
echo "  HW watchdog: /dev/watchdog0 (120s timeout)"
echo ""

# Wait a moment, then show startup
sleep 5
if kill -0 $PID 2>/dev/null; then
    echo "Status: RUNNING"
    head -20 "$LOG"
else
    echo "Status: CRASHED — check log:"
    tail -30 "$LOG"
fi
