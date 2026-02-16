#!/bin/bash

set -e

echo "[*] Downloading Nebula..."

NEBULA_VERSION="1.10.3"
ARCH="linux-amd64"

wget https://github.com/slackhq/nebula/releases/download/v${NEBULA_VERSION}/nebula-${ARCH}.tar.gz

echo "[*] Extracting..."
tar -xzf nebula-${ARCH}.tar.gz

echo "[*] Moving binary to /usr/local/bin"
sudo mv nebula /usr/local/bin/

echo "[*] Cleaning up..."
rm nebula-${ARCH}.tar.gz

echo "[✓] Nebula Installed Successfully"
