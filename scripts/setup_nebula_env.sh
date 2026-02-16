#!/bin/bash

echo "[*] Checking Nebula installation..."

if command -v nebula &> /dev/null
then
    echo "[✓] Nebula found"
    nebula --version
else
    echo "[✗] Nebula not installed"
    exit 1
fi
