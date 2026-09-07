#!/usr/bin/env python3
"""Audit log verification CLI."""

import hashlib
import json
import sys
from typing import Tuple


def verify_log(log_path: str) -> Tuple[bool, int, str]:
    expected_prev = "0" * 64
    count = 0

    with open(log_path, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f, start=1):
            raw = line.strip()
            if not raw:
                continue

            entry = json.loads(raw)
            recorded_hash = entry.get("entry_hash")

            if entry.get("prev_hash") != expected_prev:
                return (
                    False,
                    idx,
                    f"Chain break at line {idx}: expected prev_hash {expected_prev[:16]}, got {entry.get('prev_hash', '')[:16]}",
                )

            payload = {k: v for k, v in entry.items() if k != "entry_hash"}
            serialized = json.dumps(payload, sort_keys=True)
            recalculated = hashlib.sha256(serialized.encode("utf-8")).hexdigest()

            if recorded_hash != recalculated:
                return (
                    False,
                    idx,
                    f"Tamper detected at line {idx}: hash mismatch",
                )

            expected_prev = recorded_hash
            count += 1

    return True, count, expected_prev


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "audit_log.jsonl"
    try:
        ok, count, detail = verify_log(path)
        if ok:
            print(f"[PASS] Audit log intact. Verified {count} records. Tip: {detail[:16]}...")
            sys.exit(0)
        else:
            print(f"[FAIL] {detail}", file=sys.stderr)
            sys.exit(1)
    except FileNotFoundError:
        print(f"[ERROR] Log file not found: {path}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
