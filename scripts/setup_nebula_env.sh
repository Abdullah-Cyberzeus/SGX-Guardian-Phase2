#!/bin/bash

set -euo pipefail

echo "[*] Verifying Nebula environment..."

# Check nebula binary
if command -v nebula >/dev/null 2>&1; then
    echo "[✓] Nebula found"
    nebula --version
    nebula --version >/dev/null 2>&1 || { echo "[✗] Nebula binary broken"; exit 1; }
else
    echo "[✗] Nebula not found"
    exit 1
fi

# Check nebula-cert binary
if command -v nebula-cert >/dev/null 2>&1; then
    echo "[✓] Nebula-Cert found"
    nebula-cert --version >/dev/null 2>&1 || { echo "[✗] Nebula-Cert binary broken"; exit 1; }
else
    echo "[✗] Nebula-Cert not found"
    exit 1
fi

echo "[✓] Nebula environment verified successfully"
