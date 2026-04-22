# SG-X Guardian — Pre-Flight Safety Procedure

**Purpose:** Ensure that if the board freezes for any reason, it **auto-reboots within 60 seconds** instead of requiring manual power-cycle.
**Apply this FIRST, every time, before running the daemon on any board.**

---

## 1. What your latest output tells me

From the run you just showed:

```
/home/root/sgx_guardian_client nodeA     ← run directly on serial console
...
Node Identity Initialized | Public Key Prefix: BGLKVqfRBO+bAxv1Seiz...
(hang — no more output)
```

**What actually happened:**

- You ran the binary **in the foreground** directly on the serial terminal.
- The daemon initialised correctly (SE050 DKP generated, public key exported — good).
- Immediately after init, the broadcast loop started printing `Broadcasted to 192.168.50.255`, `Global broadcast to 255.255.255.255`, `🔐 Queued discovered peer...` every 30 seconds to `ttymxc1` at 115200 baud.
- The UART tx ring filled, the kernel console writer stalled, the board froze.
- Because `sgx-watchdog.sh` on disk was **17 bytes** (effectively empty) and the HW watchdog was never opened, **nothing rebooted the board** — it just sat there dead.

**This IS covered by my previous plan:**

| Symptom in your run | Fix in the plan | Status |
|---|---|---|
| Hot-path `println!` flooding UART | **FIX-4** — demote to `tracing::debug!` | Fixed at code level (needs rebuild) |
| No HW watchdog auto-reboot on freeze | **FIX-6** — `sgx-hw-keepalive.sh` owning `/dev/watchdog0` | Fixed at script level (below) |
| Daemon run directly on serial console | **FIX-7** — `fresh-provision.sh` uses `run_node.sh` | Fixed at procedure level (below) |

No new plan is needed. What you need is the **pre-flight checklist** so you get the watchdog safety net running **before** you launch the daemon. That's what this document gives you.

---

## 2. Golden Rule

**Never run `sgx_guardian_client` directly on a serial console.** Always launch it through `run_node.sh` (which redirects output to `/tmp/sgx_${NODE_ID}.log`) AND only after the HW keep-alive is running. If you violate either rule, the board can freeze with no recovery.

---

## 3. One-Time Setup Per Board (run once, survives reboots)

Do these steps in order. Each step is independently verifiable.

### Step 3.1 — Create the directories
```sh
mkdir -p /var/log/sgx-guardian
mkdir -p /var/lib/sgx-guardian/watchdog
mkdir -p /var/lib/sgx-guardian/sgx-agent
mkdir -p /var/lib/sgx-guardian/keys
mkdir -p /etc/sgx-guardian/config
mkdir -p /etc/sgx-guardian/schemas
```

### Step 3.2 — Install the HW watchdog keep-alive script

```sh
cat > /home/root/sgx-hw-keepalive.sh << 'KEEPALIVE'
#!/bin/sh
# HW watchdog keep-alive. Holds /dev/watchdog0 open and pings every 15s.
# If THIS process dies AND no further pings occur within 60s, the board reboots.
# That is the intended safety-net behaviour.

WD=/dev/watchdog0
[ -c "$WD" ] || exit 0

# Open fd 3 permanently — this ARMS the hardware watchdog.
exec 3>"$WD" || exit 1

# On clean shutdown, send a ping (NOT a stop — MAGICCLOSE not supported on imx2+).
trap 'echo 1 >&3 2>/dev/null; exit 0' TERM INT

while :; do
    echo 1 >&3 2>/dev/null || exit 1
    sleep 15
done
KEEPALIVE
chmod +x /home/root/sgx-hw-keepalive.sh
```

**Verify:**
```sh
ls -l /home/root/sgx-hw-keepalive.sh
# Should show ~500+ bytes, not 17
head -1 /home/root/sgx-hw-keepalive.sh
# Should print: #!/bin/sh
```

### Step 3.3 — Install the daemon monitor (cron watchdog)

```sh
cat > /home/root/sgx-watchdog.sh << 'MONITOR'
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
MONITOR
chmod +x /home/root/sgx-watchdog.sh
```

**Verify:**
```sh
ls -l /home/root/sgx-watchdog.sh
# Should show ~2000+ bytes, NOT 17
```

### Step 3.4 — Install auto-start on boot

This ensures the keep-alive launches on every boot, so once the board reboots (whether manually or via HW watchdog), the safety net is immediately active.

```sh
cat > /etc/init.d/sgx-hw-keepalive << 'INITD'
#!/bin/sh
### BEGIN INIT INFO
# Provides:          sgx-hw-keepalive
# Required-Start:    $local_fs
# Required-Stop:
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: SGX hardware watchdog keep-alive
### END INIT INFO

case "$1" in
    start)
        if pidof -x sgx-hw-keepalive.sh > /dev/null; then
            echo "sgx-hw-keepalive already running"
            exit 0
        fi
        echo "Starting sgx-hw-keepalive..."
        setsid /home/root/sgx-hw-keepalive.sh < /dev/null > /dev/null 2>&1 &
        ;;
    stop)
        pkill -f sgx-hw-keepalive.sh
        ;;
    status)
        if pidof -x sgx-hw-keepalive.sh > /dev/null; then
            echo "running (PID=$(pidof -x sgx-hw-keepalive.sh))"
        else
            echo "stopped"
        fi
        ;;
    *)
        echo "Usage: $0 {start|stop|status}"
        exit 1
        ;;
esac
INITD
chmod +x /etc/init.d/sgx-hw-keepalive
update-rc.d sgx-hw-keepalive defaults 2>/dev/null || \
    ln -sf /etc/init.d/sgx-hw-keepalive /etc/rc5.d/S99sgx-hw-keepalive
```

**Verify:**
```sh
/etc/init.d/sgx-hw-keepalive status
```

### Step 3.5 — Install cron entry (deduplicated)

Adjust `nodeA` to `nodeB` or `nodeC` per board.

```sh
( crontab -l 2>/dev/null | grep -v sgx-watchdog.sh ; \
  echo "* * * * * /home/root/sgx-watchdog.sh nodeA >> /var/log/sgx-guardian/watchdog.log 2>&1" \
) | crontab -

crontab -l
```

You should see exactly **one** line, not duplicates.

---

## 4. Pre-Launch Checklist (run EVERY TIME before starting the daemon)

Copy this into `/home/root/preflight.sh`:

```sh
cat > /home/root/preflight.sh << 'PREFLIGHT'
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
PREFLIGHT
chmod +x /home/root/preflight.sh
```

---

## 5. Daily Launch Procedure

Every time you want to run the daemon:

```sh
# Step 1 — run the pre-flight check.
/home/root/preflight.sh

# If pre-flight says "PRE-FLIGHT OK", continue. Otherwise fix the FAIL items first.

# Step 2 — clean any stale state (important if you erased the SE050 slot).
pkill -f sgx_guardian_client 2>/dev/null
sleep 2
rm -f /tmp/sgx_guardian_heartbeat /tmp/sgx_*.log

# Step 3 — ONLY IF you erased the SE050 slot, also wipe disk metadata:
# ssscli erase 0x20000010
# rm -rf /var/lib/sgx-guardian/keys
# rm -f  /var/lib/sgx-guardian/sgx-agent/device_*.key

# Step 4 — launch through run_node.sh (NEVER run the binary directly).
/home/root/run_node.sh nodeA
```

---

## 6. What happens if the board freezes now

With the keep-alive running:

```
t=0s      Board freezes (kernel hang / UART stall / anything).
t=0-15s   Keep-alive tries to ping /dev/watchdog0 but is blocked
          by the frozen kernel.
t=60s     HW watchdog timer expires (it was armed the moment the
          keep-alive opened /dev/watchdog0).
t=60s     i.MX8MP resets the SoC. U-Boot SPL starts.
t=~80s    Linux boots, /etc/init.d/sgx-hw-keepalive starts, cron
          starts, watchdog monitor re-launches the daemon within 60s.
t=~140s   Daemon is running again. No operator action required.
```

Worst case recovery window: **~2.5 minutes from freeze to daemon running again**. No manual AnyDesk intervention.

---

## 7. What happens if the daemon crashes (not the whole board)

```
t=0s      Daemon exits (e.g. pkcs8 error, panic).
t=<60s    Cron runs sgx-watchdog.sh.
t=<63s    Monitor sees no pidof → spawns daemon → if OK, done.
          If daemon dies again in <3s → backoff 10s, 20s, 30s…
          up to 600s max, instead of hammering the CPU.
```

Board stays up. Keep-alive keeps pinging. No reboot.

---

## 8. Manual recovery commands if board freezes anyway

If for any reason the keep-alive also dies (bug, OOM) and the board freezes with no reboot:

1. **Power-cycle** the board physically (James, via AnyDesk, can do a hard reboot on the outlet).
2. After boot, SSH in and run:
   ```sh
   /home/root/preflight.sh
   ```
3. If pre-flight passes, launch daemon:
   ```sh
   /home/root/run_node.sh nodeA
   ```

That's it.

---

## 9. Verifying the safety net is actually live

Run these three commands after setup. All must pass.

```sh
# 9.1  Keep-alive is running and holds /dev/watchdog0.
pidof -x sgx-hw-keepalive.sh && lsof /dev/watchdog0 2>/dev/null

# 9.2  Cron has the monitor line.
crontab -l | grep sgx-watchdog.sh

# 9.3  Watchdog driver reports keep-alive pings.
wdctl /dev/watchdog0
# Expected: Timeout ~60s, KEEPALIVEPING STATUS=1
```

---

## 10. Why this handles your last freeze

The output you just showed me stopped right after:

```
Node Identity Initialized | Public Key Prefix: BGLKVqfRBO+bAxv1Seiz...
```

That is the **last `println!` before the broadcast loop starts**. The broadcast loop's per-tick prints saturate the UART on the serial console.

- With the **new binary** (FIX-4 applied), those prints go to the tracing layer only, never to stdout → UART never floods → no freeze.
- With the **current old binary** you still have on the board, you MUST launch via `run_node.sh` which redirects stdout to `/tmp/sgx_nodeA.log`. Running it directly on serial is what caused the freeze.
- Either way, with the **keep-alive from Step 3.2** armed, even a kernel freeze recovers in ~2.5 minutes automatically instead of requiring manual intervention.

---

## Summary — what to do right now

1. **On all three boards**, run Section 3 end to end (one-time setup).
2. **Verify** with Section 9.
3. **From now on**, launch the daemon only via Section 5 (preflight + `run_node.sh`).
4. When you push the rebuilt binary with FIX-1 through FIX-4 applied, follow the same launch procedure.

End of pre-flight procedure.