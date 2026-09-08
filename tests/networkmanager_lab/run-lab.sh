#!/usr/bin/env bash
set -euo pipefail

readonly LAB_NAMESPACE="sgx-upstream"
readonly LAB_PROFILE="sgx-test-uplink"
readonly LAB_INTERFACE="wlan1"
readonly LAB_PEER="upstream0"
readonly LAB_NETWORK="10.77.0.0/24"
readonly LAB_GATEWAY="10.77.0.1"
readonly LAB_RANGE_START="10.77.0.10"
readonly LAB_RANGE_END="10.77.0.20"

nm_pid=""
dnsmasq_pid=""

cleanup() {
    if [[ -n "${nm_pid}" ]]; then
        kill "${nm_pid}" 2>/dev/null || true
        wait "${nm_pid}" 2>/dev/null || true
    fi
    if [[ -n "${dnsmasq_pid}" ]]; then
        kill "${dnsmasq_pid}" 2>/dev/null || true
        wait "${dnsmasq_pid}" 2>/dev/null || true
    fi
    ip netns delete "${LAB_NAMESPACE}" 2>/dev/null || true
}
trap cleanup EXIT

fail() {
    echo "FAIL: $*" >&2
    if [[ -f /tmp/NetworkManager.log ]]; then
        tail -n 80 /tmp/NetworkManager.log >&2 || true
    fi
    exit 1
}

mkdir -p /run/dbus /run/NetworkManager /tmp/nm-connections /tmp/nm-conf.d
chmod 700 /tmp/nm-connections

dbus-uuidgen --ensure=/etc/machine-id
dbus-daemon --system --fork --nopidfile
/lib/systemd/systemd-udevd --daemon
udevadm trigger --subsystem-match=net
udevadm settle

ip netns add "${LAB_NAMESPACE}"
ip link add "${LAB_INTERFACE}" type veth peer name "${LAB_PEER}"
ip link set "${LAB_PEER}" netns "${LAB_NAMESPACE}"
ip netns exec "${LAB_NAMESPACE}" ip link set lo up
ip netns exec "${LAB_NAMESPACE}" ip address add "${LAB_GATEWAY}/24" dev "${LAB_PEER}"
ip netns exec "${LAB_NAMESPACE}" ip link set "${LAB_PEER}" up
ip link set "${LAB_INTERFACE}" up

ip netns exec "${LAB_NAMESPACE}" dnsmasq \
    --no-daemon \
    --interface="${LAB_PEER}" \
    --bind-interfaces \
    --dhcp-range="${LAB_RANGE_START},${LAB_RANGE_END},255.255.255.0,1h" \
    --dhcp-option="3,${LAB_GATEWAY}" \
    --dhcp-option="6,${LAB_GATEWAY}" \
    --pid-file= \
    >/tmp/dnsmasq.log 2>&1 &
dnsmasq_pid=$!

cat >/tmp/NetworkManager.conf <<'EOF'
[main]
plugins=keyfile
auth-polkit=false

[ifupdown]
managed=true

[device-wlan1]
match-device=interface-name:wlan1
managed=1

[logging]
level=INFO
domains=ALL
EOF

NetworkManager \
    --debug \
    --no-daemon \
    --config=/tmp/NetworkManager.conf \
    --config-dir=/tmp/nm-conf.d \
    --system-config-dir=/tmp/nm-connections \
    >/tmp/NetworkManager.log 2>&1 &
nm_pid=$!

for _ in $(seq 1 20); do
    if nmcli general status >/dev/null 2>&1; then
        break
    fi
    sleep 0.25
done
nmcli general status >/dev/null 2>&1 || fail "NetworkManager did not become ready"

nmcli device set "${LAB_INTERFACE}" managed yes \
    || fail "could not mark ${LAB_INTERFACE} managed"

for _ in $(seq 1 20); do
    state=$(nmcli -g GENERAL.STATE device show "${LAB_INTERFACE}" 2>/dev/null || true)
    if [[ "${state}" != 10* ]]; then
        break
    fi
    sleep 0.25
done

echo "NetworkManager: $(nmcli --version)"
echo "Isolated topology: ${LAB_INTERFACE} <-> ${LAB_NAMESPACE}/${LAB_PEER} (${LAB_NETWORK})"
nmcli -f DEVICE,TYPE,STATE device status

nmcli connection add \
    type ethernet \
    ifname "${LAB_INTERFACE}" \
    con-name "${LAB_PROFILE}" \
    connection.autoconnect no \
    ipv4.method auto \
    ipv6.method disabled \
    >/dev/null

nmcli --wait 20 connection up "${LAB_PROFILE}" \
    || fail "initial DHCP activation failed"

assigned_address=$(nmcli -g IP4.ADDRESS device show "${LAB_INTERFACE}" | head -n 1)
[[ "${assigned_address}" == 10.77.0.*/* ]] \
    || fail "unexpected DHCP address: ${assigned_address:-none}"

ip netns exec "${LAB_NAMESPACE}" ping -c 1 -W 2 "${assigned_address%/*}" >/dev/null \
    || fail "namespace peer cannot reach ${assigned_address}"

nmcli connection down "${LAB_PROFILE}" >/dev/null \
    || fail "deactivation failed"
nmcli --wait 20 connection up "${LAB_PROFILE}" >/dev/null \
    || fail "reactivation failed"

reactivated_address=$(nmcli -g IP4.ADDRESS device show "${LAB_INTERFACE}" | head -n 1)
[[ "${reactivated_address}" == 10.77.0.*/* ]] \
    || fail "reactivation did not restore DHCP: ${reactivated_address:-none}"

echo "PASS: isolated NetworkManager activation, DHCP, reachability, deactivation, and reactivation"
echo "NOTE: veth validates lifecycle only; wireless scan/association still requires mac80211_hwsim or board 252"
