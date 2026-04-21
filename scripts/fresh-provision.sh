#!/bin/sh
NODE_ID="${1:-nodeA}"

echo "[+] Stopping any running daemon..."
pkill -f sgx_guardian_client 2>/dev/null
sleep 2

echo "[+] Clearing SE050 DKP slot..."
ssscli erase 0x20000010 2>/dev/null

echo "[+] Clearing on-disk DKP metadata + keys..."
rm -rf /var/lib/sgx-guardian/keys
rm -f  /var/lib/sgx-guardian/sgx-agent/device_*.key
rm -f  /tmp/sgx_guardian_heartbeat
rm -f  /tmp/sgx_${NODE_ID}.log

echo "[+] Ensuring log dir + state dir exist..."
mkdir -p /var/log/sgx-guardian /var/lib/sgx-guardian/watchdog

echo "[+] Starting HW watchdog keep-alive..."
pkill -f sgx-hw-keepalive.sh 2>/dev/null
setsid /home/root/sgx-hw-keepalive.sh < /dev/null > /dev/null 2>&1 &

echo "[+] Launching daemon..."
/home/root/run_node.sh "$NODE_ID"
