#!/usr/bin/env bash
set -euo pipefail

readonly UPLINK_INTERFACE="wlan1"
readonly PROTECTED_INTERFACE="wlan0"
readonly AP_INTERFACE="uap0"
readonly SERVICE_USER="sgxguardian"

failures=0

pass() {
    echo "PASS: $*"
}

fail() {
    echo "FAIL: $*" >&2
    failures=$((failures + 1))
}

require_command() {
    if command -v "$1" >/dev/null 2>&1; then
        pass "$1 is installed"
    else
        fail "$1 is not installed"
    fi
}

echo "SGX NetworkManager M0 board preflight (read-only)"
echo "Protected interface: ${PROTECTED_INTERFACE}"
echo "Candidate NM uplink: ${UPLINK_INTERFACE}"
echo "Guardian AP interface: ${AP_INTERFACE}"

require_command nmcli
require_command systemctl
require_command ip
require_command iw

if (( failures > 0 )); then
    exit 1
fi

nmcli --version

if [[ "$(systemctl is-active NetworkManager 2>/dev/null || true)" == "active" ]]; then
    pass "NetworkManager is active"
else
    fail "NetworkManager is not active"
fi

echo
nmcli -f DEVICE,TYPE,STATE,CONNECTION device status

if ip link show dev "${PROTECTED_INTERFACE}" >/dev/null 2>&1; then
    protected_state=$(nmcli -g GENERAL.STATE device show "${PROTECTED_INTERFACE}" 2>/dev/null || true)
    pass "${PROTECTED_INTERFACE} exists and was only inspected (state: ${protected_state:-unknown})"
else
    fail "protected interface ${PROTECTED_INTERFACE} does not exist"
fi

if ip link show dev "${AP_INTERFACE}" >/dev/null 2>&1; then
    pass "Guardian AP interface ${AP_INTERFACE} exists"
else
    fail "Guardian AP interface ${AP_INTERFACE} does not exist"
fi

if ip link show dev "${UPLINK_INTERFACE}" >/dev/null 2>&1; then
    pass "candidate uplink ${UPLINK_INTERFACE} exists"
else
    fail "candidate uplink ${UPLINK_INTERFACE} does not exist"
fi

uplink_type=$(nmcli -g GENERAL.TYPE device show "${UPLINK_INTERFACE}" 2>/dev/null || true)
uplink_managed=$(nmcli -g GENERAL.NM-MANAGED device show "${UPLINK_INTERFACE}" 2>/dev/null || true)
uplink_state=$(nmcli -g GENERAL.STATE device show "${UPLINK_INTERFACE}" 2>/dev/null || true)

if [[ "${uplink_type}" == "wifi" ]]; then
    pass "${UPLINK_INTERFACE} is a NetworkManager Wi-Fi device"
else
    fail "${UPLINK_INTERFACE} has unexpected NetworkManager type: ${uplink_type:-missing}"
fi

if [[ "${uplink_managed}" == "yes" ]]; then
    pass "${UPLINK_INTERFACE} is managed by NetworkManager"
else
    fail "${UPLINK_INTERFACE} is not managed by NetworkManager: ${uplink_managed:-unknown}"
fi

echo "INFO: ${UPLINK_INTERFACE} state is ${uplink_state:-unknown}; preflight does not change it"

if id "${SERVICE_USER}" >/dev/null 2>&1 && command -v runuser >/dev/null 2>&1; then
    permissions=$(runuser -u "${SERVICE_USER}" -- \
        nmcli -t -f PERMISSION,VALUE general permissions 2>/dev/null || true)
    echo
    echo "NetworkManager permissions for ${SERVICE_USER}:"
    if [[ -n "${permissions}" ]]; then
        echo "${permissions}"
    else
        fail "could not read NetworkManager permissions as ${SERVICE_USER}"
    fi

    for permission in \
        org.freedesktop.NetworkManager.network-control \
        org.freedesktop.NetworkManager.wifi.scan \
        org.freedesktop.NetworkManager.settings.modify.system \
        org.freedesktop.NetworkManager.checkpoint-rollback
    do
        value=$(awk -F: -v wanted="${permission}" '$1 == wanted { print $2 }' <<<"${permissions}")
        if [[ "${value}" == "yes" ]]; then
            pass "${SERVICE_USER} has ${permission}"
        else
            fail "${SERVICE_USER} permission ${permission} is ${value:-missing}"
        fi
    done
else
    fail "service user ${SERVICE_USER} or runuser is unavailable"
fi

echo
echo "Wireless topology (read-only):"
iw dev

if (( failures > 0 )); then
    echo
    echo "M0 PREFLIGHT FAILED: ${failures} check(s) need attention" >&2
    exit 1
fi

echo
echo "M0 PREFLIGHT PASSED: no interfaces were modified"
