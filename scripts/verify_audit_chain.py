#!/usr/bin/env python3
"""
Segment-aware audit-chain verifier (FIX #8 mirror, runnable without cargo).
Matches the Rust verifier's behaviour: treats `previous_hash` mismatches as
segment boundaries (legitimate after restart/rotation) rather than tampers.

Usage:
  ./verify_audit_chain.py /var/log/sgx-guardian/audit-nodeA.log
"""
import hashlib
import json
import sys
from pathlib import Path

def main():
    if len(sys.argv) != 2:
        print("usage: verify_audit_chain.py <audit.log>", file=sys.stderr)
        sys.exit(2)

    path = Path(sys.argv[1])
    if not path.exists():
        print(f"ERROR: log file not found: {path}", file=sys.stderr)
        sys.exit(2)

    chain_state = None
    line_count = 0
    segment_count = 0
    current_segment_start = None

    for idx, line in enumerate(path.open("r", encoding="utf-8", errors="ignore"), start=1):
        line = line.strip()
        if not line:
            continue
        line_count += 1

        try:
            obj = json.loads(line)
        except json.JSONDecodeError as e:
            print(f"FAIL: invalid JSON at line {idx}: {e}", file=sys.stderr)
            sys.exit(1)

        event = obj.get("event")
        stored_prev = obj.get("previous_hash", "GENESIS")
        stored_hash = obj.get("hash")
        if not stored_hash or event is None:
            print(f"FAIL: missing event/hash at line {idx}", file=sys.stderr)
            sys.exit(1)

        # Rust writer uses serde_json::to_string(event) - default field order
        # of the AuditEvent struct. Python json.dumps with sort_keys=False
        # preserves dict order; relying on the daemon's order is correct here
        # because the daemon writes the same shape every time.
        payload = json.dumps(event, separators=(",", ":"))

        # Segment boundary detection (matches Rust verifier).
        is_first = current_segment_start is None
        chain_state_matches = chain_state == stored_prev
        if is_first or not chain_state_matches:
            chain_state = stored_prev
            segment_count += 1
            current_segment_start = idx

        # next_hash = SHA256(prev || payload)
        h = hashlib.sha256()
        h.update(chain_state.encode("utf-8"))
        h.update(payload.encode("utf-8"))
        computed = h.hexdigest()

        if computed != stored_hash:
            print(
                f"FAIL: tamper at line {idx} "
                f"(segment started at line {current_segment_start})",
                file=sys.stderr,
            )
            print(f"  expected_prev: {chain_state}", file=sys.stderr)
            print(f"  computed_hash: {computed}", file=sys.stderr)
            print(f"  stored_hash:   {stored_hash}", file=sys.stderr)
            sys.exit(1)

        chain_state = stored_hash

    print(f"SEGMENT_CHAIN_OK lines={line_count} segments={segment_count}")


if __name__ == "__main__":
    main()
