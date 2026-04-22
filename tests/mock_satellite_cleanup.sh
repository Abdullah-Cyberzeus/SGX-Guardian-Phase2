#!/usr/bin/env bash
set -euo pipefail

sudo tc qdisc del dev sat0 root 2>/dev/null || true
sudo ip link del sat0 2>/dev/null || true
echo "Mock satellite interface removed"
