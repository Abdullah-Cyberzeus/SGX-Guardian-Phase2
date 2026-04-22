#!/usr/bin/env bash
set -euo pipefail

# Create mock satellite interface with Iridium-like characteristics.
if ip link show sat0 >/dev/null 2>&1; then
  echo "sat0 already exists"
else
  sudo ip tuntap add mode tun dev sat0
fi

sudo ip addr add 10.100.0.1/30 dev sat0 2>/dev/null || true
sudo ip link set dev sat0 up

sudo tc qdisc del dev sat0 root 2>/dev/null || true
sudo tc qdisc add dev sat0 root handle 1: netem delay 1500ms loss 3%
# Best-effort shaping; skip if kernel/qdisc parent is unsupported.
sudo tc qdisc add dev sat0 parent 1:1 handle 10: tbf rate 88kbit burst 1kb latency 50ms 2>/dev/null || true

echo "Mock satellite interface 'sat0' ready"
echo "  Address:    10.100.0.1/30"
echo "  Latency:    ~1500ms"
echo "  Loss:       3%"
echo "  Bandwidth:  88 kbps"
