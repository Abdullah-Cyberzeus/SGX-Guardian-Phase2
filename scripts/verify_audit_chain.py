#!/usr/bin/env python3
"""Verify SGX Guardian audit log hash chaining."""

import argparse
import hashlib
import json
import sys
from pathlib import Path


GENESIS = "GENESIS"


def compact_json(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def verify(path):
    last_hash = GENESIS
    line_count = 0
    segment_count = 0
    current_segment_start = None

    try:
        fh = path.open("r", encoding="utf-8")
    except OSError as e:
        print(f"ERROR: cannot open log file: {e}", file=sys.stderr)
        sys.exit(2)

    with fh:
        for idx, line in enumerate(fh, start=1):
            if not line.strip():
                continue
            line_count += 1

            try:
                record = json.loads(line)
            except json.JSONDecodeError as e:
                print(f"ERROR: invalid JSON at line {idx}: {e}", file=sys.stderr)
                sys.exit(1)

            event = record.get("event")
            stored_prev = record.get("previous_hash", GENESIS)
            stored_hash = record.get("hash")
            if event is None:
                print(f"ERROR: missing event field at line {idx}", file=sys.stderr)
                sys.exit(1)
            if stored_hash is None:
                print(f"ERROR: missing hash field at line {idx}", file=sys.stderr)
                sys.exit(1)

            if current_segment_start is None or stored_prev != last_hash:
                last_hash = stored_prev
                segment_count += 1
                current_segment_start = idx

            payload = compact_json(event)
            computed = hashlib.sha256((last_hash + payload).encode("utf-8")).hexdigest()
            last_hash = computed
            if computed != stored_hash:
                print(
                    "ERROR: AUDIT LOG TAMPER DETECTED at line "
                    f"{idx} (within segment starting at line {current_segment_start})",
                    file=sys.stderr,
                )
                sys.exit(1)

    print(f"OK: {line_count} entries verified across {segment_count} segment(s)")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path, help="audit log path")
    args = parser.parse_args()
    verify(args.path)


if __name__ == "__main__":
    main()
