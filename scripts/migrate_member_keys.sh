#!/usr/bin/env bash
#
# migrate_member_keys.sh — remove member private keys from a Guardian CA (P0.2).
#
# Background
# ----------
# Before the Phase 0 hotfix the CA ran `nebula-cert sign -out-key`, so it
# generated and stored a private key for every member it ever enrolled, under
# <nebula>/nodes/<member>.key. Those files are a standing compromise: anyone who
# reads the CA's disk holds every member's Nebula identity.
#
# After the hotfix each Guardian generates its own key and the CA only ever
# writes <member>.crt. This script cleans up the keys the old CA already wrote.
#
# Safety
# ------
# * The CA's OWN key (nodes/<this guardian>.key) is never touched, and neither
#   is ca/ca.key. Both are legitimately the CA's.
# * A member key is only removed once the member has confirmed it holds its own
#   copy — see --confirmed below. Removing a key for a member still running the
#   legacy flow would leave it unable to start Nebula.
# * Nothing is deleted without a backup, unless --no-backup is given.
# * The default mode is a dry run.
#
# Usage
#   scripts/migrate_member_keys.sh --guardian-id <id> [options]
#
#   --guardian-id <id>   This CA's own Guardian id, whose key is preserved.
#                        Defaults to the mesh profile's guardian_id.
#   --confirmed <list>   Comma-separated member ids that have confirmed they
#                        hold their own key. Only these are removed.
#   --all                Treat every member as confirmed. Use only when the
#                        whole fleet is known to be upgraded.
#   --apply              Actually delete. Without it, this is a dry run.
#   --no-backup          Skip the backup archive (not recommended).
#   --nebula-dir <path>  Default /var/lib/sgx-guardian/nebula
#
set -euo pipefail

NEBULA_DIR="/var/lib/sgx-guardian/nebula"
PROFILE="/var/lib/sgx-guardian/mesh/profile.json"
GUARDIAN_ID=""
CONFIRMED=""
ALL=0
APPLY=0
BACKUP=1

die() { printf '❌ %s\n' "$1" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --guardian-id) GUARDIAN_ID="${2:-}"; shift 2 ;;
    --confirmed)   CONFIRMED="${2:-}";   shift 2 ;;
    --nebula-dir)  NEBULA_DIR="${2:-}";  shift 2 ;;
    --all)         ALL=1;      shift ;;
    --apply)       APPLY=1;    shift ;;
    --no-backup)   BACKUP=0;   shift ;;
    -h|--help)     sed -n '2,38p' "$0"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[[ -d "$NEBULA_DIR" ]] || die "no Nebula directory at $NEBULA_DIR"
[[ -f "$NEBULA_DIR/ca/ca.key" ]] || die "$NEBULA_DIR/ca/ca.key not found — this does not look like a CA"

# Fall back to the mesh profile for this CA's own id, so the operator does not
# have to repeat what the daemon already knows.
if [[ -z "$GUARDIAN_ID" && -f "$PROFILE" ]]; then
  GUARDIAN_ID="$(sed -n 's/.*"guardian_id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$PROFILE" | head -1)"
fi
[[ -n "$GUARDIAN_ID" ]] || die "could not determine this CA's guardian id — pass --guardian-id"

if [[ $ALL -eq 0 && -z "$CONFIRMED" ]]; then
  die "pass --confirmed <ids> for members that hold their own key, or --all"
fi

is_confirmed() {
  [[ $ALL -eq 1 ]] && return 0
  local needle="$1"
  IFS=',' read -ra ids <<< "$CONFIRMED"
  for id in "${ids[@]}"; do
    [[ "${id// /}" == "$needle" ]] && return 0
  done
  return 1
}

printf '🔍 Scanning %s/nodes for member private keys\n' "$NEBULA_DIR"
printf '   This CA is "%s" — its own key is preserved.\n\n' "$GUARDIAN_ID"

to_remove=()
skipped=()
shopt -s nullglob
for key in "$NEBULA_DIR"/nodes/*.key; do
  member="$(basename "$key" .key)"
  if [[ "$member" == "$GUARDIAN_ID" ]]; then
    printf '   keep    %-20s (this CA'\''s own key)\n' "$member"
    continue
  fi
  if [[ ! -f "$NEBULA_DIR/nodes/$member.crt" ]]; then
    printf '   keep    %-20s (no certificate — partial state, review by hand)\n' "$member"
    skipped+=("$member")
    continue
  fi
  if is_confirmed "$member"; then
    printf '   REMOVE  %-20s (confirmed: member holds its own key)\n' "$member"
    to_remove+=("$key")
  else
    printf '   keep    %-20s (not confirmed — member may still rely on this key)\n' "$member"
    skipped+=("$member")
  fi
done
shopt -u nullglob

printf '\n'
if [[ ${#to_remove[@]} -eq 0 ]]; then
  printf '✅ Nothing to remove.\n'
  [[ ${#skipped[@]} -gt 0 ]] && printf '   Still holding keys for: %s\n' "${skipped[*]}"
  exit 0
fi

if [[ $APPLY -eq 0 ]]; then
  printf '🧪 Dry run — %d key(s) would be removed. Re-run with --apply.\n' "${#to_remove[@]}"
  exit 0
fi

if [[ $BACKUP -eq 1 ]]; then
  archive="$NEBULA_DIR/member-keys-backup-$(date -u +%Y%m%dT%H%M%SZ).tar.gz"
  tar -czf "$archive" -C "$NEBULA_DIR/nodes" \
    "${to_remove[@]/#$NEBULA_DIR\/nodes\//}"
  chmod 600 "$archive"
  printf '💾 Backup written to %s (mode 0600)\n' "$archive"
  printf '   Move it off this host and destroy it once the fleet is verified —\n'
  printf '   it contains exactly the material this migration exists to remove.\n'
fi

for key in "${to_remove[@]}"; do
  rm -f -- "$key"
  printf '   removed %s\n' "$key"
done

printf '\n✅ Removed %d member private key(s).\n' "${#to_remove[@]}"
[[ ${#skipped[@]} -gt 0 ]] && printf '⚠️  Still holding keys for: %s\n' "${skipped[*]}"
printf '   Verify with: ls %s/nodes/*.key\n' "$NEBULA_DIR"
printf '   Only %s.key should remain.\n' "$GUARDIAN_ID"
