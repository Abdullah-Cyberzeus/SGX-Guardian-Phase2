#!/bin/bash
# inject_alerts.sh — Simulates a burst of Suricata EVE JSON alerts
# Writes mock alert lines directly to the EVE log file that SGX tails.
#
# Usage: sudo ./scripts/inject_alerts.sh [count] [src_ip] [category] [severity]
# Example (CRITICAL burst): sudo ./scripts/inject_alerts.sh 60 "192.168.1.105" "reconnaissance" "high"
# Example (low volume):     sudo ./scripts/inject_alerts.sh 3  "10.0.0.5"      "reconnaissance" "low"

COUNT=${1:-50}
SRC_IP=${2:-"192.168.1.105"}
CATEGORY=${3:-"reconnaissance"}
SEVERITY=${4:-"high"}
EVE_FILE="/var/log/suricata/eve.json"

# Suricata signature IDs mapped by category
case "$CATEGORY" in
    "reconnaissance")        SID=2009358; SIG="ET SCAN Nmap OS Detection Probe" ;;
    "exploit")               SID=2019401; SIG="ET EXPLOIT OpenSSL Heartbleed Response" ;;
    "malware")               SID=2001219; SIG="ET MALWARE ELF.Mirai Variant Checkin" ;;
    "policy-violation"|"policy_violation") SID=2014819; SIG="ET POLICY Suspicious Outbound Connection" ;;
    "attestation_mismatch")  SID=3000001; SIG="ATTESTATION TPM PCR Mismatch Detected" ;;
    "certificate_issue")     SID=3000002; SIG="PKI Invalid Certificate / Expired Handshake" ;;
    "anomaly")               SID=2260002; SIG="SURICATA Anomaly Invalid TCP" ;;
    *)                       SID=2009358; SIG="ET SCAN Generic Scan" ;;
esac

echo "========================================"
echo "SGX Alert Injector"
echo "========================================"
echo "  Count    : $COUNT"
echo "  Src IP   : $SRC_IP"
echo "  Category : $CATEGORY"
echo "  Severity : $SEVERITY"
echo "  SID      : $SID"
echo "  EVE File : $EVE_FILE"
echo "========================================"

# Ensure the EVE log file exists
if [ ! -f "$EVE_FILE" ]; then
    echo "Creating $EVE_FILE..."
    mkdir -p "$(dirname $EVE_FILE)"
    touch "$EVE_FILE"
    chmod 644 "$EVE_FILE"
fi

echo "Injecting $COUNT alerts..."

for i in $(seq 1 $COUNT); do
    TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%S.%3N+0000")
    FLOW_ID=$((RANDOM * RANDOM + i))
    SRC_PORT=$((RANDOM % 64000 + 1024))

    NUM_SEV=1
    if [ "$SEVERITY" = "low" ]; then NUM_SEV=3; fi

    printf '{"timestamp":"%s","flow_id":%d,"in_iface":"eth0","event_type":"alert","src_ip":"%s","src_port":%d,"dest_ip":"10.0.0.1","dest_port":8443,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":%d,"rev":7,"signature":"%s","category":"%s","severity":%d},"app_proto":"http","severity":"%s"}\n' \
        "$TIMESTAMP" "$FLOW_ID" "$SRC_IP" "$SRC_PORT" "$SID" "$SIG" "$CATEGORY" "$NUM_SEV" "$SEVERITY" \
        >> "$EVE_FILE"

    # Small delay to avoid I/O spike
    sleep 0.01

    # Progress every 10 alerts
    if [ $((i % 10)) -eq 0 ]; then
        echo "  ... $i/$COUNT alerts written"
    fi
done

echo ""
echo "Done. $COUNT alerts injected to $EVE_FILE"
echo ""
echo "Wait ~3 seconds then check:"
echo "  curl -sk https://localhost:8443/api/v1/threat/advisories | python3 -m json.tool"
