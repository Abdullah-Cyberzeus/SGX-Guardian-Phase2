#!/bin/sh
# Pre-flight safety checklist. Run before every daemon launch.

echo "=== SGX Guardian Pre-Flight ==="
FAIL=0

# 1. HW watchdog keep-alive must be running.
if pidof -x sgx-hw-keepalive.sh > /dev/null; then
    echo "[OK]   HW watchdog keep-alive running (PID=$(pidof -x sgx-hw-keepalive.sh))"
else
    echo "[FAIL] HW watchdog keep-alive NOT running — starting..."
    setsid /home/root/sgx-hw-keepalive.sh < /dev/null > /dev/null 2>&1 &
    sleep 2
    if pidof -x sgx-hw-keepalive.sh > /dev/null; then
        echo "[OK]   Keep-alive started (PID=$(pidof -x sgx-hw-keepalive.sh))"
    else
        echo "[FAIL] Could not start keep-alive — ABORT"
        FAIL=1
    fi
fi

# 2. Watchdog device must exist.
if [ -c /dev/watchdog0 ]; then
    echo "[OK]   /dev/watchdog0 present"
else
    echo "[FAIL] /dev/watchdog0 missing"
    FAIL=1
fi

# 3. Cron monitor must be scheduled.
if crontab -l 2>/dev/null | grep -q sgx-watchdog.sh; then
    echo "[OK]   Cron monitor scheduled"
else
    echo "[WARN] Cron monitor not scheduled (daemon won't auto-restart if it crashes)"
fi

# 4. Log/state directories must exist.
for d in /var/log/sgx-guardian /var/lib/sgx-guardian/watchdog \
         /var/lib/sgx-guardian/keys /var/lib/sgx-guardian/sgx-agent; do
    if [ -d "$d" ]; then
        echo "[OK]   $d exists"
    else
        mkdir -p "$d"
        echo "[OK]   $d created"
    fi
done

# 5. Binary must be executable and NOT the old .disabled suffix.
if [ -x /home/root/sgx_guardian_client ]; then
    SIZE=$(stat -c %s /home/root/sgx_guardian_client)
    echo "[OK]   Binary present (${SIZE} bytes)"
else
    echo "[FAIL] /home/root/sgx_guardian_client missing or not executable"
    FAIL=1
fi

# 6. run_node.sh must exist and be sane (> 200 bytes).
if [ -x /home/root/run_node.sh ]; then
    SIZE=$(stat -c %s /home/root/run_node.sh)
    if [ "$SIZE" -gt 200 ]; then
        echo "[OK]   run_node.sh present (${SIZE} bytes)"
    else
        echo "[FAIL] run_node.sh too small (${SIZE} bytes) — possibly truncated"
        FAIL=1
    fi
else
    echo "[FAIL] /home/root/run_node.sh missing"
    FAIL=1
fi

# 7. sgx-watchdog.sh must NOT be the broken 17-byte stub.
if [ -x /home/root/sgx-watchdog.sh ]; then
    SIZE=$(stat -c %s /home/root/sgx-watchdog.sh)
    if [ "$SIZE" -gt 500 ]; then
        echo "[OK]   sgx-watchdog.sh present (${SIZE} bytes)"
    else
        echo "[FAIL] sgx-watchdog.sh truncated (${SIZE} bytes) — reinstall from Step 3.3"
        FAIL=1
    fi
fi

echo ""
if [ "$FAIL" -eq 0 ]; then
    echo "=== PRE-FLIGHT OK — safe to launch daemon ==="
    echo "Next: /home/root/run_node.sh nodeA   (or nodeB / nodeC)"
    exit 0
else
    echo "=== PRE-FLIGHT FAILED — do NOT launch daemon ==="
    exit 1
fi
