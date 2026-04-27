#!/bin/bash

set -e

echo "[*] Downloading Nebula..."

NEBULA_VERSION="1.10.3"
case "$(uname -m)" in
    x86_64)  ARCH="linux-amd64" ;;
    aarch64) ARCH="linux-arm64" ;;
    armv7l)  ARCH="linux-arm-7" ;;
    *)       echo "[!] Unsupported architecture: $(uname -m)"; exit 1 ;;
esac

BASE_URL="https://github.com/slackhq/nebula/releases/download/v${NEBULA_VERSION}"
wget "${BASE_URL}/nebula-${ARCH}.tar.gz"
wget "${BASE_URL}/SHASUM256.txt"

echo "[*] Verifying checksum..."
grep "nebula-${ARCH}.tar.gz" SHASUM256.txt | sha256sum -c - || {
    echo "[!] Checksum verification failed"; exit 1;
}

echo "[*] Extracting..."
tar -xzf nebula-${ARCH}.tar.gz

echo "[*] Moving binaries to /usr/local/bin"
sudo mv nebula /usr/local/bin/
sudo mv nebula-cert /usr/local/bin/

echo "[*] Setting executable permissions"
sudo chmod +x /usr/local/bin/nebula
sudo chmod +x /usr/local/bin/nebula-cert

echo "[*] Cleaning up..."
rm nebula-${ARCH}.tar.gz SHASUM256.txt

echo "[✓] Nebula & Nebula-Cert Installed Successfully"
