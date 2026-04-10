#!/bin/bash
# scripts/verify_nebula_overlay.sh
# ============================================================
# Complete verification script for the Nebula overlay network.
# Run this on EACH node after starting the guardian daemon.
# ============================================================

set -euo pipefail

NODE_ID="${1:-nodeA}"
NEBULA_BASE="/var/lib/sgx-guardian/nebula"

section() { echo; echo "══════════════════════════════════════════════════"; echo "  $1"; echo "══════════════════════════════════════════════════"; }
ok()      { echo "  ✅ $1"; }
warn()    { echo "  ⚠️  $1"; }
fail()    { echo "  ❌ $1"; }

# ── 1. CA FINGERPRINT CHECK ──────────────────────────────────────────────
section "1. CA Fingerprint"

if [ -f "$NEBULA_BASE/ca/ca.crt" ]; then
    FP=$(nebula-cert print -json -path "$NEBULA_BASE/ca/ca.crt" 2>/dev/null \
         | python3 -c "import sys,json; d=json.load(sys.stdin); \
           fp=d.get('details',{}).get('fingerprint') or d.get('fingerprint','?'); \
           print(fp[:16])" 2>/dev/null || sha256sum "$NEBULA_BASE/ca/ca.crt" | cut -c1-16)
    ok "CA cert present. Fingerprint prefix: $FP"
    echo "     >>> Compare with nodeA — they MUST match <<<"
else
    fail "CA cert missing at $NEBULA_BASE/ca/ca.crt"
    echo "     If this is nodeB/C: restart guardian (it will fetch from nodeA)"
fi

# ── 2. NODE CERT CHECK ───────────────────────────────────────────────────
section "2. Node Certificate"

CERT="$NEBULA_BASE/nodes/$NODE_ID.crt"
KEY="$NEBULA_BASE/nodes/$NODE_ID.key"

if [ -f "$CERT" ] && [ -f "$KEY" ]; then
    ok "Cert and key present for $NODE_ID"
    # Print cert overlay IP
    IP=$(nebula-cert print -json -path "$CERT" 2>/dev/null \
         | python3 -c "import sys,json; d=json.load(sys.stdin); \
           ips=d.get('details',{}).get('ips',['?']); print(ips[0] if isinstance(ips,list) else ips)" \
         2>/dev/null || echo "?")
    ok "Overlay IP in cert: $IP"
else
    fail "Cert or key missing for $NODE_ID"
fi

# ── 3. NEBULA CONFIG CHECK ───────────────────────────────────────────────
section "3. Nebula Config"

CFG="$NEBULA_BASE/nebula.yaml"
AM_LH=""
LH_ENDPOINTS=""

if [ -f "$CFG" ]; then
    ok "Config exists: $CFG"
    
    if grep -q "LIGHTHOUSE_PUBLIC_IP\|NEEDS_NODE" "$CFG"; then
        fail "Config still contains placeholder IP!"
        echo "  Fix: ensure nodeA is running and SGX_LIGHTHOUSE_IP is set on member nodes"
    else
        ok "No placeholder IP detected"
    fi

    STATIC=$(grep -A2 "static_host_map:" "$CFG" | head -5)
    echo "  static_host_map section:"
    echo "$STATIC" | sed 's/^/    /'

    AM_LH=$(grep -E "^[[:space:]]*am_lighthouse:" "$CFG" | awk '{print $2}' | head -1 || true)
    if [ "$AM_LH" = "true" ]; then
        ok "Config role: lighthouse (am_lighthouse: true)"
    elif [ "$AM_LH" = "false" ]; then
        ok "Config role: member (am_lighthouse: false)"
    else
        warn "Could not parse am_lighthouse role"
    fi

    LH_ENDPOINTS=$(grep -A10 "static_host_map:" "$CFG" \
        | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:4242' || true)

    if [ "$AM_LH" = "true" ]; then
        if grep -q "static_host_map: {}" "$CFG"; then
            ok "Lighthouse static_host_map is empty as expected"
        else
            warn "Lighthouse static_host_map is not empty"
        fi
    elif [ "$AM_LH" = "false" ]; then
        if [ -n "$LH_ENDPOINTS" ]; then
            ok "Member static_host_map has real lighthouse endpoint(s): $(echo "$LH_ENDPOINTS" | tr '\n' ' ')"
        else
            fail "Member static_host_map missing real endpoint(s)"
        fi

        LH_HOST_COUNT=$(grep -A10 "lighthouse:" "$CFG" | grep -cE '^[[:space:]]*-[[:space:]]*"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+"' || true)
        if [ "$LH_HOST_COUNT" -ge 1 ]; then
            ok "lighthouse.hosts entries: $LH_HOST_COUNT"
        else
            fail "No lighthouse.hosts entries found for member node"
        fi
    fi

    # Validate config
    if nebula -config "$CFG" -test >/dev/null 2>&1; then
        ok "Config validated by nebula -test"
    else
        fail "Config validation FAILED:"
        nebula -config "$CFG" -test 2>&1 | sed 's/^/    /'
    fi
else
    fail "Config missing: $CFG"
fi

# ── 4. NEBULA DAEMON STATUS ──────────────────────────────────────────────
section "4. Nebula Daemon"

if pgrep -f "nebula -config" >/dev/null 2>&1; then
    PID=$(pgrep -f "nebula -config" | head -1)
    ok "Nebula daemon running (PID $PID)"
else
    fail "Nebula daemon NOT running"
    echo "  Start: nebula -config $CFG &"
fi

# ── 5. NEBULA0 INTERFACE ─────────────────────────────────────────────────
section "5. nebula0 Interface"

if ip link show nebula0 >/dev/null 2>&1; then
    STATE=$(ip link show nebula0 | grep -oP '(?<=state )\w+')
    ok "nebula0 exists (state: $STATE)"
    
    IP=$(ip addr show nebula0 2>/dev/null | grep 'inet ' | awk '{print $2}' | head -1)
    if [ -n "$IP" ]; then
        ok "nebula0 IP: $IP"
    else
        fail "nebula0 has no IP assigned"
        echo "  Fix: sudo ip addr add <overlay-ip>/24 dev nebula0 && sudo ip link set nebula0 up"
    fi
    
    RX=$(cat /sys/class/net/nebula0/statistics/rx_bytes 2>/dev/null || echo "?")
    TX=$(cat /sys/class/net/nebula0/statistics/tx_bytes 2>/dev/null || echo "?")
    echo "  Traffic: rx=${RX}B tx=${TX}B"
    if [ "$RX" = "0" ] && [ "$TX" = "0" ]; then
        warn "No traffic — overlay tunnel not yet established"
    fi
else
    fail "nebula0 interface does not exist"
    echo "  This usually means:"
    echo "    a) Nebula daemon failed to start — check logs"
    echo "    b) TUN/TAP kernel module not loaded: sudo modprobe tun"
    echo "    c) No CAP_NET_ADMIN — run as root or with sudo"
fi

# ── 6. UDP 4242 CONNECTIVITY ─────────────────────────────────────────────
section "6. UDP 4242 Reachability"

if ss -ulnp 2>/dev/null | grep -q ":4242"; then
    ok "Local UDP 4242 listener detected"
else
    fail "Local UDP 4242 listener NOT detected"
fi

if [ "$AM_LH" != "true" ]; then
    PRIMARY_LH_ENDPOINT=$(echo "$LH_ENDPOINTS" | head -1 || true)
    if [ -n "$PRIMARY_LH_ENDPOINT" ]; then
        NODE_A_IP="${PRIMARY_LH_ENDPOINT%:4242}"
        echo "  Testing UDP 4242 to lighthouse at $PRIMARY_LH_ENDPOINT..."
        if nc -zu -w3 "$NODE_A_IP" 4242 2>/dev/null; then
            ok "UDP 4242 reachable to $PRIMARY_LH_ENDPOINT"
        else
            fail "UDP 4242 NOT reachable to $PRIMARY_LH_ENDPOINT"
            echo "  Fix on nodeA: sudo ufw allow 4242/udp  OR  sudo nft add rule inet filter input udp dport 4242 accept"
        fi
    else
        warn "Could not parse lighthouse endpoint from static_host_map"
    fi
else
    echo "  (remote reachability skipped — this node is configured as lighthouse)"
fi

# ── 7. OVERLAY PING TEST ─────────────────────────────────────────────────
section "7. Overlay Ping"

if [ "$NODE_ID" = "nodeA" ]; then
    echo "  Testing ping to nodeB (192.168.100.2) and nodeC (192.168.100.3)..."
    for target in 192.168.100.2 192.168.100.3; do
        if ping -c3 -W2 -I nebula0 "$target" >/dev/null 2>&1; then
            ok "Overlay ping to $target: OK"
        else
            fail "Overlay ping to $target: FAILED"
        fi
    done
else
    echo "  Testing ping to nodeA (192.168.100.1)..."
    if ping -c3 -W2 -I nebula0 192.168.100.1 >/dev/null 2>&1; then
        ok "Overlay ping to 192.168.100.1: OK"
    else
        fail "Overlay ping to 192.168.100.1: FAILED"
        echo "  Check: nebula daemon logs on both nodes"
        echo "  Check: ca.crt fingerprint matches (step 1 above)"
    fi
fi

# ── 8. FIREWALL CHECK ────────────────────────────────────────────────────
section "8. Firewall (nftables)"

if command -v nft >/dev/null 2>&1; then
    if nft list ruleset 2>/dev/null | grep -q "udp dport 4242"; then
        ok "nftables allows UDP 4242"
    else
        warn "UDP 4242 not found in nftables ruleset"
        echo "  Add: sudo nft add rule inet sgx_guardian input udp dport 4242 accept"
        echo "  Or check enforcement/executor.rs includes the Nebula rules"
    fi
else
    echo "  (nft not available — check firewall manually)"
fi

# ── SUMMARY ──────────────────────────────────────────────────────────────
section "Summary"
echo "  Run this script on BOTH nodes and compare CA fingerprints."
echo "  They MUST match.  If they differ, delete the member's ca/ dir and restart."
echo ""
echo "  Useful commands:"
echo "    Watch nebula logs:  sudo journalctl -fu nebula"
echo "    Show overlay stats: watch -n1 ip addr show nebula0"
echo "    Manual ping:        ping -c5 -I nebula0 192.168.100.1"
echo "    Validate config:    nebula -config $CFG -test"
echo ""
