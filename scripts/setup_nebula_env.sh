#!/bin/bash

echo "[*] Verifying Nebula environment..."

# Check nebula binary
if command -v nebula >/dev/null 2>&1; then
    echo "[✓] Nebula found"
    nebula --version
else
    echo "[✗] Nebula not found"
    exit 1
fi

# Check nebula-cert binary
if command -v nebula-cert >/dev/null 2>&1; then
    echo "[✓] Nebula-Cert found"
else
    echo "[✗] Nebula-Cert not found"
    exit 1
fi

echo "[✓] Nebula environment verified successfully"
