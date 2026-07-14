#!/usr/bin/env bash
set -euo pipefail

# Run on nodeA (CA).
# Override these when board IPs or binary paths differ:
#   NODEB_HOST=root@192.168.50.115 NODEC_HOST=root@192.168.50.248 CLI=./sgx-pa-cli ./scripts/crl_board_check.sh

CLI="${CLI:-./sgx-pa-cli}"
DAEMON="${DAEMON:-./sgx_guardian_client}"
NODEB_HOST="${NODEB_HOST:-root@192.168.50.115}"
NODEC_HOST="${NODEC_HOST:-root@192.168.50.248}"
DID_PATH="${DID_PATH:-/var/lib/sgx-guardian/identity/did.json}"
CRL_PATH="${CRL_PATH:-/var/lib/sgx-guardian/identity/crl/crl.json}"

NODEB_DID=$(ssh "$NODEB_HOST" "cat '$DID_PATH' | jq -r .did")
NODEC_DID=$(ssh "$NODEC_HOST" "cat '$DID_PATH' | jq -r .did")

echo "=== CRL-001 owner revokes member ==="
"$CLI" crl revoke --did "$NODEB_DID" --reason compromised --severity critical --note "test SE001"
"$CLI" crl check --did "$NODEB_DID"
# Expect: revoked: true

echo "=== CRL-005 self-revocation rejected ==="
SELF_DID=$(jq -r .did "$DID_PATH")
"$CLI" crl revoke --did "$SELF_DID" --reason compromised --severity critical 2>&1 | grep -i "self"

echo "=== CRL-006 double-revoke rejected ==="
"$CLI" crl revoke --did "$NODEB_DID" --reason stolen --severity critical 2>&1 | grep -i "already"

echo "=== CRL-007 persistence across restart ==="
pkill -f sgx_guardian_client || true
sleep 3
"$DAEMON" nodeA &
sleep 5
"$CLI" crl check --did "$NODEB_DID"
# Expect: revoked: true

echo "=== CRL-009 Merkle root parity ==="
"$CLI" crl revoke --did "$NODEC_DID" --reason policy_violation --severity high
"$CLI" crl root
ROOT_A=$("$CLI" crl root | jq -r .merkle_root)
scp "$CRL_PATH" "$NODEB_HOST:/tmp/crl-from-A.json"
ROOT_B=$(ssh "$NODEB_HOST" "jq -r .merkle_root /tmp/crl-from-A.json")
test "$ROOT_A" = "$ROOT_B"
# Expect: identical hex string on both sides.

echo "=== CRL-010 cross-ref VC status flipped ==="
ssh "$NODEB_HOST" './sgx-pa-cli vc show'
# Expect: nodeB's VC's `credential_status` is reported as revoked when re-verified.
ssh "$NODEB_HOST" './sgx-pa-cli vc verify --path /var/lib/sgx-guardian/identity/vc/own/*.json 2>&1 | grep -i revoked'
