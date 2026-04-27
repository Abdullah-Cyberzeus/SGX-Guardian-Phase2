#!/bin/sh
# Stream kernel ring buffer to a file while daemon runs. Lets us see if
# the kernel is hitting softlockup / RCU stall warnings that cause SSH resets.

OUT=/tmp/sgx_kmsg.log
echo "=== kmsg watch started at $(date -u) ===" > "$OUT"
dmesg -w >> "$OUT" 2>&1 &
echo $! > /tmp/sgx_kmsg.pid
echo "kmsg watch PID $(cat /tmp/sgx_kmsg.pid), log: $OUT"
