#!/bin/sh
set -e

# Install Nmap dependency required by Sprint 6 discovery workflows.
echo "→ Installing nmap (Sprint 6 NMP-series)..."

# FIX #6: package-manager-aware install. Yocto boards have neither apt nor dnf;
# nmap must be in the BSP image or installed manually. Don't hard-fail here —
# install.sh runs on dev boxes (apt), prod RHEL (dnf), and boards (opkg/skip).
install_nmap() {
    if command -v apt-get >/dev/null 2>&1; then
        apt-get install -y nmap || return 1
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y nmap || return 1
    elif command -v opkg >/dev/null 2>&1; then
        opkg update && opkg install nmap || return 1
    else
        echo "⚠ No supported package manager (apt/dnf/opkg) on this system."
        echo "  If you're on a Yocto board, ensure nmap is in the BSP image,"
        echo "  or scp it from a built sysroot. Skipping install step."
        return 0
    fi
}
install_nmap

if command -v nmap >/dev/null 2>&1; then
    setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip "$(command -v nmap)" || {
        echo "⚠ setcap failed — NMAP will fall back to TCP-connect mode."
    }
    echo "✓ nmap at $(command -v nmap), caps: $(getcap "$(command -v nmap)" 2>/dev/null)"
else
    echo "⚠ nmap not on PATH after install attempt — Discovery scheduler will report"
    echo "  BinaryMissing error until nmap is available. This is non-fatal."
fi
