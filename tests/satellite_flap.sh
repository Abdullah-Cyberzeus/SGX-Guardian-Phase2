#!/usr/bin/env bash
set -euo pipefail

while true; do
  sleep 30
  sudo ip link set sat0 down
  echo "[flap] sat0 DOWN"
  sleep 15
  sudo ip link set sat0 up
  echo "[flap] sat0 UP"
done
