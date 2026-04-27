#!/bin/sh
# Daemon monitor — runs from cron every minute.
# Does NOT touch /dev/watchdog0 (that is the keep-alive's job).
# Restarts daemon if missing, with exponential backoff to prevent thrash.

HEARTBEAT="/tmp/sgx_guardian_heartbeat"
NODE_ID="${1:-nodeA}"
MAX_AGE=120
LOG="/var/log/sgx-guardian/watchdog.log"
STATE_DIR="/var/lib/sgx-guardian/watchdog"
FAIL_COUNTER="$STATE_DIR/fail_count.$NODE_ID"
BACKOFF_STAMP="$STATE_DIR/backoff_until.$NODE_ID"

mkdir -p "$(dirname "$LOG")" "$STATE_DIR" 2>/dev/null

log_msg() { echo "$(date '+%Y-%m-%d %H:%M:%S') [$NODE_ID] $1" >> "$LOG"; }
now_ts() { date +%s; }

if [ -f "$BACKOFF_STAMP" ]; then
    until=$(cat "$BACKOFF_STAMP" 2>/dev/null || echo 0)
    if [ "$(now_ts)" -lt "$until" ]; then
        log_msg "INFO: in backoff window until $until — skipping"
        exit 0
    else
        rm -f "$BACKOFF_STAMP"
    fi
fi

DAEMON_PID=$(pidof sgx_guardian_client 2>/dev/null)

if [ -z "$DAEMON_PID" ]; then
    FC=0
    [ -f "$FAIL_COUNTER" ] && FC=$(cat "$FAIL_COUNTER" 2>/dev/null || echo 0)
    FC=$((FC + 1))
    echo "$FC" > "$FAIL_COUNTER"

    log_msg "WARN: daemon not running (fail#$FC) — starting"
    /home/root/sgx_guardian_client "$NODE_ID" > /tmp/sgx_${NODE_ID}.log 2>&1 &
    sleep 3
    NEW_PID=$(pidof sgx_guardian_client 2>/dev/null)

    if [ -z "$NEW_PID" ]; then
        BACKOFF=$((10 * FC))
        [ "$BACKOFF" -gt 600 ] && BACKOFF=600
        echo "$(( $(now_ts) + BACKOFF ))" > "$BACKOFF_STAMP"
        log_msg "ERROR: daemon failed to start — backing off ${BACKOFF}s"
    else
        echo 0 > "$FAIL_COUNTER"
        log_msg "INFO: daemon started (PID=$NEW_PID)"
    fi
    exit 0
fi

echo 0 > "$FAIL_COUNTER"

if [ ! -f "$HEARTBEAT" ]; then
    log_msg "INFO: no heartbeat yet (daemon may be initializing)"
    exit 0
fi

FILE_TIME=$(stat -c %Y "$HEARTBEAT" 2>/dev/null || echo 0)
NOW=$(now_ts)
AGE=$((NOW - FILE_TIME))

if [ "$AGE" -gt "$MAX_AGE" ]; then
    log_msg "CRITICAL: heartbeat stale (${AGE}s > ${MAX_AGE}s) — restarting daemon"
    kill -TERM "$DAEMON_PID" 2>/dev/null
    sleep 3
    kill -KILL "$DAEMON_PID" 2>/dev/null
    rm -f "$HEARTBEAT"
    /home/root/sgx_guardian_client "$NODE_ID" > /tmp/sgx_${NODE_ID}.log 2>&1 &
    sleep 2
    log_msg "INFO: daemon restarted (PID=$(pidof sgx_guardian_client))"
fi
