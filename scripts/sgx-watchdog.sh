#!/bin/sh
# SGX Guardian Watchdog — monitors daemon heartbeat
# If daemon is stuck for >600s (10 min), restart it.
# Also kicks hardware watchdog to prevent board reboot
# if daemon is healthy.

HEARTBEAT="/tmp/sgx_guardian_heartbeat"
NODE_ID="${1:-nodeA}"
MAX_AGE=600  # 10 minutes in seconds
LOG="/var/log/sgx-guardian/watchdog.log"

log_msg() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') $1" >> "$LOG"
}

# Kick hardware watchdog (keeps board alive)
if [ -e /dev/watchdog0 ]; then
    echo "V" > /dev/watchdog0 2>/dev/null
fi

# Check if daemon process exists
DAEMON_PID=$(pidof sgx_guardian_client 2>/dev/null)

if [ -z "$DAEMON_PID" ]; then
    log_msg "WARN: daemon not running — starting"
    /root/sgx_guardian_client "$NODE_ID" > /tmp/sgx_${NODE_ID}.log 2>&1 &
    sleep 2
    log_msg "INFO: daemon started (PID=$(pidof sgx_guardian_client))"
    exit 0
fi

# Check heartbeat file age
if [ ! -f "$HEARTBEAT" ]; then
    log_msg "WARN: no heartbeat file yet — daemon may still be starting"
    exit 0
fi

# Get file age in seconds
FILE_TIME=$(stat -c %Y "$HEARTBEAT" 2>/dev/null || echo 0)
NOW=$(date +%s)
AGE=$((NOW - FILE_TIME))

if [ "$AGE" -gt "$MAX_AGE" ]; then
    log_msg "CRITICAL: heartbeat stale (${AGE}s > ${MAX_AGE}s) — killing daemon"
    kill -9 "$DAEMON_PID" 2>/dev/null
    sleep 3
    # Clean up stale state
    rm -f "$HEARTBEAT"
    # Restart
    /root/sgx_guardian_client "$NODE_ID" > /tmp/sgx_${NODE_ID}.log 2>&1 &
    sleep 2
    log_msg "INFO: daemon restarted (PID=$(pidof sgx_guardian_client))"
else
    # Daemon is healthy — just log occasionally
    if [ "$((AGE % 300))" -lt 60 ]; then
        log_msg "OK: daemon healthy (heartbeat ${AGE}s ago, PID=$DAEMON_PID)"
    fi
fi
