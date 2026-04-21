# 3-Issue Fix Plan (Latest Main Branch)


## Issue 1: Board Still Freezes Despite UART Drain

### Root Cause
The UART drain delays help but don't fully prevent freezes because the daemon's **periodic broadcast loop** outputs 2 lines every 30 seconds indefinitely. After startup completes, the serial keeps receiving `Broadcasted to...` and `Global broadcast to...` lines plus `🔐 Queued discovered peer...` and `Config updated...` lines. Over time, especially when attestation retry loops run (15 retries × 1 second × print each), the serial buffer overflows again.

### Solution: Boss's Approach — Watchdog + Heartbeat + Timeout

Instead of trying to prevent ALL serial overflow (which is impossible at 115200 baud), use the i.MX8MP hardware watchdog so the board auto-recovers if it freezes. This is the industrial-grade solution.

**Implementation:** Add a heartbeat file that the daemon touches every 30 seconds. A systemd watchdog service monitors this file. If the daemon stops updating it (frozen), systemd restarts it. If the whole board freezes, the hardware watchdog reboots it.

### Code Changes in `src/main.rs`

#### Change 1.1: Add heartbeat writer to the background uptime tracker

**FIND:**
```rust
    // background uptime tracker
    let node_id_clone = node_id.clone();
    let metrics_clone = metrics.clone();
    tokio::spawn(async move {
        loop {
            {
                let m = metrics_clone.lock().await;
                let uptime = m.uptime().as_secs();
                log_event(&node_id_clone, &format!("Uptime: {} seconds", uptime));
            }
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    });
```

**REPLACE WITH:**
```rust
    // background uptime tracker + heartbeat writer
    let node_id_clone = node_id.clone();
    let metrics_clone = metrics.clone();
    tokio::spawn(async move {
        let heartbeat_path = "/tmp/sgx_guardian_heartbeat";
        loop {
            {
                let m = metrics_clone.lock().await;
                let uptime = m.uptime().as_secs();
                log_event(&node_id_clone, &format!("Uptime: {} seconds", uptime));
            }
            // Write heartbeat file — external watchdog monitors this
            let _ = std::fs::write(heartbeat_path, chrono::Utc::now().to_rfc3339());
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    });
```

#### Change 1.2: Suppress repetitive broadcast output in `src/node_broadcast.rs`

**FIND in `src/node_broadcast.rs`:**
```rust
    match socket.send_to(bytes, subnet_addr) {
        Ok(n) => println!("Broadcasted to {} ({} bytes)", subnet_addr, n),
        Err(e) => eprintln!("Subnet broadcast failed: {}", e),
    }

    let global_addr = SocketAddrV4::new(Ipv4Addr::BROADCAST, port);
    match socket.send_to(bytes, global_addr) {
        Ok(n) => println!("Global broadcast to {} ({} bytes)", global_addr, n),
        Err(e) => eprintln!("Global broadcast failed: {}", e),
    }
```

**REPLACE WITH:**
```rust
    match socket.send_to(bytes, subnet_addr) {
        Ok(_) => {} // Silent — reduces UART flood on boards
        Err(e) => eprintln!("Subnet broadcast failed: {}", e),
    }

    let global_addr = SocketAddrV4::new(Ipv4Addr::BROADCAST, port);
    match socket.send_to(bytes, global_addr) {
        Ok(_) => {} // Silent — reduces UART flood on boards
        Err(e) => eprintln!("Global broadcast failed: {}", e),
    }
```

**REASONING:** These 2 lines print every 30 seconds forever. On the board that's 4 lines/minute of output the serial doesn't need. Silencing them dramatically reduces post-startup serial load.

#### Change 1.3: Suppress repetitive config update messages in `src/dynamic_config.rs`

**FIND in `src/dynamic_config.rs`:**
```rust
        match std::fs::write(&path, &result) {
            Ok(_) => println!("Config updated (field-level): {} -> ip={}", node_id, ip),
            Err(e) => eprintln!("Config write failed: {} -> {}", path, e),
        }
```

**REPLACE WITH:**
```rust
        match std::fs::write(&path, &result) {
            Ok(_) => {} // Silent — config updates happen frequently, no need to print each one
            Err(e) => eprintln!("Config write failed: {} -> {}", path, e),
        }
```

Also **FIND** the "Config unchanged" line if present:
```rust
            Ok(_) => println!("Config unchanged (field-level): {} -> ip={}", node_id, ip),
```

**REPLACE WITH:**
```rust
            Ok(_) => {} // Silent — unchanged configs don't need printing
```

---


## Issue 2: Hardware Attestation Not Working

### Root Cause (from laptop logs — also applies on boards)

The attestation listener has a **self-attestation guard** that incorrectly drops legitimate peer connections:

```rust
// In start_attestation_listener():
let local_overlay = overlay_ip_from_local_registry(&local_node_id);
if let Some(ref ovl) = local_overlay {
    if remote.ip().to_string() == *ovl {
        continue;  // ← BUG: drops connection WITHOUT reading/responding
    }
}
```

**What happens:**
1. nodeB connects to nodeA's attestation listener at `192.168.100.1:50151`
2. On the same machine (laptop), the TCP source IP is `192.168.100.1` (shared nebula0)
3. The guard sees `remote.ip() == local_overlay` → drops the socket via `continue`
4. nodeB tries to write evidence → gets `Broken pipe (os error 32)`

**On boards:** The guard checks `remote.ip()` against `local_overlay`. On boards with separate nebula0 interfaces, nodeB connects from `192.168.100.2` so the guard shouldn't trigger. BUT if the overlay IP lookup returns the wrong value (e.g., if the registry hasn't synced yet, or if nodeA's registry shows nodeA's own overlay IP for a peer), it could still silently drop connections.

**There's a SECOND problem:** The guard drops connections with `continue` which silently closes the TCP socket. The connecting peer sees `Broken pipe` but no error message is logged on the listener side. This makes debugging impossible.

**There's a THIRD problem:** When the attestation listener drops a connection, the connecting node retries 15 times × 1 second each. That's 15 lines of `⏳ Waiting for peer...` output — more UART flood.

### Code Changes in `src/attestation_service.rs`

#### Change 2.1: Fix the self-attestation guard to compare node IDs, not IPs

**FIND:**
```rust
            Ok((mut socket, remote)) => {
                let local_node_id = std::env::args().nth(1).unwrap_or_else(|| "nodeA".into());
                let local_overlay = overlay_ip_from_local_registry(&local_node_id);
                if let Some(ref ovl) = local_overlay {
                    if remote.ip().to_string() == *ovl {
                        continue;
                    }
                }

                println!("📩 Received attestation request from peer");
```

**REPLACE WITH:**
```rust
            Ok((mut socket, remote)) => {
                // NOTE: Self-attestation guard removed from listener side.
                // The SENDER side already guards against self-attestation
                // (by node_id check and overlay IP check in the discovery loop).
                // The listener should accept ALL valid connections and let
                // cryptographic verification handle trust decisions.
                // The old IP-based guard was causing "Broken pipe" errors
                // when peers shared the same nebula0 interface (same-machine tests)
                // or when overlay IPs hadn't synced yet.

                println!("📩 Received attestation request from {}", remote.ip());
```

**REASONING:** The guard is redundant because the SENDER side already prevents self-attestation (see the `if peer_node_id == local_node_id { continue; }` check in the discovery loop). Removing it from the listener fixes Broken pipe on same-machine AND prevents silent drops on boards if overlay IPs are out of sync.

#### Change 2.2: Reduce retry count to prevent UART flood

**FIND:**
```rust
const CONNECT_RETRY_ATTEMPTS: u8 = 15;
```

**REPLACE WITH:**
```rust
const CONNECT_RETRY_ATTEMPTS: u8 = 5;
```

**REASONING:** 15 retries × 1 second = 15 seconds of blocking + 15 lines of output per failed peer. With 2 peers, that's 30 lines of `⏳ Waiting...` if both are offline. Reducing to 5 cuts this to 10 lines max. The 60-second re-attestation timer will retry anyway.

#### Change 2.3: Silence repetitive "Queued discovered peer" messages

**FIND (all instances in the `run()` function and `p2p_discovery.rs`):**
```rust
        println!("🔐 Queued discovered peer for attestation: {}", target_key);
```

Or similar like:
```rust
        println!("🔐 Queued discovered peer for attestation (config-scan): {}:{}", ...);
```

**REPLACE WITH (each instance):**
```rust
        // Silenced — peer queue messages repeat every 30s and flood UART
```

The first-time discovery message `"🔐 Attesting discovered peer over overlay: ..."` should remain — it only prints once per actual attestation attempt.

---


## Issue 3: Watchdog + Heartbeat + Timeout Setup Guide

### Architecture

```
┌─────────────────────────────────┐
│  sgx_guardian_client daemon     │
│  ├─ writes /tmp/sgx_guardian_   │
│  │  heartbeat every 30 seconds  │
│  └─ if frozen, stops writing    │
└─────────────────────────────────┘
          ↓ monitors ↓
┌─────────────────────────────────┐
│  sgx-watchdog.sh (cron/systemd) │
│  ├─ checks heartbeat file age  │
│  ├─ if > 600s (10min): kill +  │
│  │  restart the daemon          │
│  └─ also kicks /dev/watchdog0   │
└─────────────────────────────────┘
          ↓ if system frozen ↓
┌─────────────────────────────────┐
│  Hardware watchdog (i.MX8MP)    │
│  /dev/watchdog0                 │
│  timeout: 120 seconds           │
│  if no kick → full board reboot │
└─────────────────────────────────┘
```

### Step 1: Create the watchdog script on each board

```bash
cat > /root/sgx-watchdog.sh << 'WATCHDOG'
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
WATCHDOG
chmod +x /root/sgx-watchdog.sh
```

### Step 2: Set up cron to run watchdog every 60 seconds

```bash
# Add to crontab
(crontab -l 2>/dev/null; echo "* * * * * /root/sgx-watchdog.sh nodeA >> /var/log/sgx-guardian/watchdog.log 2>&1") | crontab -

# For board 2 (nodeB):
# (crontab -l 2>/dev/null; echo "* * * * * /root/sgx-watchdog.sh nodeB >> /var/log/sgx-guardian/watchdog.log 2>&1") | crontab -

# For board 3 (nodeC):
# (crontab -l 2>/dev/null; echo "* * * * * /root/sgx-watchdog.sh nodeC >> /var/log/sgx-guardian/watchdog.log 2>&1") | crontab -

# Verify
crontab -l
```

### Step 3: Enable hardware watchdog (i.MX8MP built-in)

The i.MX8MP has a hardware watchdog at `/dev/watchdog0`. If nothing kicks it within the timeout, the SoC performs a hardware reset — equivalent to pulling the power cable.

```bash
# Check if hardware watchdog exists
ls -la /dev/watchdog*
# Expected: /dev/watchdog0

# The watchdog is already loaded by the kernel:
dmesg | grep -i watchdog
# Expected: "imx2-wdt 30280000.watchdog: timeout 60 sec"

# Set timeout to 120 seconds (2 minutes)
# The watchdog script kicks it every 60s, so 120s timeout means
# 2 missed kicks = board reboot
echo 120 > /sys/class/watchdog/watchdog0/timeout 2>/dev/null || true

# Start the hardware watchdog (once started, MUST be kicked or board reboots)
# The watchdog script handles kicking via "echo V > /dev/watchdog0"
```

**IMPORTANT:** Once you open `/dev/watchdog0`, you MUST keep kicking it or the board reboots. The cron-based watchdog script does this automatically every 60 seconds. If cron itself freezes (which is extremely rare — cron is a kernel-level service), the hardware watchdog triggers a full board reboot after 120 seconds.

### Step 4: Create the run script (updated with watchdog integration)

```bash
cat > /root/run_node.sh << 'SCRIPT'
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
SCRIPT
chmod +x /root/run_node.sh
```

### How the 3-Layer Protection Works

```
Layer 1: DAEMON HEARTBEAT (10 minute tolerance)
  - Daemon writes /tmp/sgx_guardian_heartbeat every 30s
  - If daemon thread is stuck but process is alive:
    → heartbeat stops updating
    → after 600s, watchdog.sh kills and restarts daemon
  - Board does NOT reboot — only daemon restarts

Layer 2: PROCESS MONITOR (cron every 60s)
  - If daemon crashes completely (process gone):
    → watchdog.sh detects no PID
    → immediately restarts daemon
  - Board does NOT reboot — only daemon restarts

Layer 3: HARDWARE WATCHDOG (120 second timeout)
  - If the entire board freezes (kernel hang, OOM, etc.):
    → cron can't run → watchdog.sh can't kick /dev/watchdog0
    → after 120s with no kick → i.MX8MP hardware resets
    → Board fully reboots from scratch
    → Daemon auto-starts via cron on next boot
```

### Key Points
- **Board only reboots if the entire system is truly frozen** (kernel-level hang)
- **Daemon crash** → auto-restart within 60 seconds (no reboot)
- **Daemon hang** → auto-restart within 10 minutes (no reboot)
- **Total system freeze** → hardware reboot within 2 minutes
- **Normal operation** → nothing happens, daemon runs indefinitely

### Auto-Start on Boot (Optional)

To make the daemon start automatically on every boot:

```bash
cat > /etc/init.d/sgx-guardian << 'INIT'
#!/bin/sh
### BEGIN INIT INFO
# Provides:          sgx-guardian
# Required-Start:    $network $remote_fs
# Required-Stop:     $network
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Description:       SGX Guardian Client
### END INIT INFO

NODE_ID="nodeA"  # Change per board: nodeA, nodeB, nodeC

case "$1" in
    start)
        echo "Starting SGX Guardian ($NODE_ID)..."
        /root/run_node.sh $NODE_ID
        ;;
    stop)
        echo "Stopping SGX Guardian..."
        pkill -f sgx_guardian_client 2>/dev/null
        ;;
    restart)
        $0 stop
        sleep 2
        $0 start
        ;;
    status)
        PID=$(pidof sgx_guardian_client 2>/dev/null)
        if [ -n "$PID" ]; then
            echo "Running (PID $PID)"
            cat /tmp/sgx_guardian_heartbeat 2>/dev/null
        else
            echo "Not running"
        fi
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status}"
        exit 1
        ;;
esac
INIT
chmod +x /etc/init.d/sgx-guardian
update-rc.d sgx-guardian defaults 2>/dev/null || true
```

---

## Verification Commands After All 3 Fixes Applied

### Build and deploy
```bash
# On laptop
cargo build --release --features secure-element
cargo build --release -p sgx-pa-cli

# Deploy
scp -C target/aarch64-unknown-linux-gnu/release/sgx_guardian_client root@BOARD_IP:/root/
scp -C target/aarch64-unknown-linux-gnu/release/sgx-pa-cli root@BOARD_IP:/root/
```

### On the board
```bash
# Set up watchdog first
chmod +x /root/sgx-watchdog.sh /root/run_node.sh
(crontab -l 2>/dev/null; echo "* * * * * /root/sgx-watchdog.sh nodeA") | crontab -

# Start the daemon (ALWAYS via run_node.sh)
./run_node.sh nodeA

# Verify heartbeat is being written
sleep 40
cat /tmp/sgx_guardian_heartbeat
# Should show a recent timestamp

# Verify watchdog log
cat /var/log/sgx-guardian/watchdog.log
# Should show "OK: daemon healthy" entries

# Test watchdog recovery (simulate freeze)
kill -STOP $(pidof sgx_guardian_client)  # Freeze the daemon
# Wait 10+ minutes...
# Watchdog should kill and restart it
cat /var/log/sgx-guardian/watchdog.log | tail -5
# Should show "CRITICAL: heartbeat stale" then "INFO: daemon restarted"

# Resume the frozen daemon (cleanup)
kill -CONT $(pidof sgx_guardian_client) 2>/dev/null

# Check attestation between boards
./sgx-pa-cli peers
./sgx-pa-cli attestation
```