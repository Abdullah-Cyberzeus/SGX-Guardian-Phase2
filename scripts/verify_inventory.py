#!/usr/bin/env python3
"""
Inventory verification helper for boards without jq.
Usage:
  ./verify_inventory.py /var/lib/sgx-guardian/discovery/inventory.json
  ./verify_inventory.py inventory.json --unauthorized
  ./verify_inventory.py inventory.json --duplicate-macs
  ./verify_inventory.py inventory.json --status approved
"""
import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path", type=Path)
    ap.add_argument("--status", choices=["approved", "unauthorized", "drifted", "stale"])
    ap.add_argument("--unauthorized", action="store_true")
    ap.add_argument("--duplicate-macs", action="store_true")
    ap.add_argument("--ip", help="filter by exact IP")
    ap.add_argument("--mac", help="filter by MAC (case-insensitive)")
    ap.add_argument("--count", action="store_true", help="just print count")
    args = ap.parse_args()

    try:
        data = json.loads(args.path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        print(f"ERROR: inventory file not found: {args.path}", file=sys.stderr)
        sys.exit(2)
    except json.JSONDecodeError as e:
        print(f"ERROR: inventory not valid JSON: {e}", file=sys.stderr)
        sys.exit(3)

    if not isinstance(data, list):
        print("ERROR: inventory root is not an array", file=sys.stderr)
        sys.exit(4)

    out = data

    if args.unauthorized:
        out = [d for d in out if d.get("status") in ("unauthorized", "drifted")]
    if args.status:
        out = [d for d in out if d.get("status") == args.status]
    if args.ip:
        out = [d for d in out if d.get("ip") == args.ip]
    if args.mac:
        m = args.mac.upper()
        out = [d for d in out if (d.get("mac") or "").upper() == m]

    if args.duplicate_macs:
        groups = defaultdict(list)
        for d in data:
            if d.get("mac"):
                groups[d["mac"].upper()].append(d.get("ip"))
        dupes = {m: ips for m, ips in groups.items() if len(ips) > 1}
        if dupes:
            print(f"FAIL: {len(dupes)} MAC(s) appear on multiple IPs:")
            for m, ips in dupes.items():
                print(f"  {m} -> {ips}")
            sys.exit(1)
        else:
            print("OK: no duplicate MACs in inventory.")
            sys.exit(0)

    if args.count:
        print(len(out))
        return

    # Default: compact one-line summary per device.
    for d in out:
        print(json.dumps({
            "ip": d.get("ip"),
            "mac": d.get("mac"),
            "status": d.get("status"),
            "hostname": d.get("hostname"),
            "vendor": d.get("vendor"),
            "open_ports": [p.get("port") for p in d.get("open_ports", [])],
        }))


if __name__ == "__main__":
    main()
