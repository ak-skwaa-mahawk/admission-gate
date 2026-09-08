#!/usr/bin/env python3
"""
admission_gate.query - Zero-dependency audit log forensic query and replay tool.
"""

import argparse
import json
import os
import sys
import time
from typing import Any, Dict, Iterator, Optional

from admission_gate.config import GateConfig, find_default_config
from admission_gate.gate import ActionProposal, PolicyEngine


def parse_relative_time(time_str: str) -> float:
    """Parses relative time strings (e.g., '10m', '2h', '1d') into epoch seconds."""
    time_str = time_str.strip().lower()
    now = time.time()
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400}

    unit = time_str[-1]
    if unit in units:
        try:
            val = float(time_str[:-1])
            return now - (val * units[unit])
        except ValueError:
            pass
    try:
        return float(time_str)
    except ValueError:
        raise ValueError(f"Invalid timestamp or relative window: {time_str}")


def stream_entries(log_path: str) -> Iterator[Dict[str, Any]]:
    if not os.path.exists(log_path):
        raise FileNotFoundError(f"Log file not found: {log_path}")

    with open(log_path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as e:
                print(f"Warning: line {line_num} malformed JSON: {e}", file=sys.stderr)


def filter_entries(
    log_path: str,
    action_id: Optional[str] = None,
    tier: Optional[int] = None,
    status: Optional[str] = None,
    since_ts: Optional[float] = None,
    until_ts: Optional[float] = None,
) -> Iterator[Dict[str, Any]]:
    for entry in stream_entries(log_path):
        prop = entry.get("proposal", {})

        if action_id and prop.get("action_id") != action_id:
            continue

        effective_tier = entry.get("effective_risk_tier", prop.get("risk_tier", 1))
        if tier is not None and effective_tier != tier:
            continue

        if status:
            passed = entry.get("policy_passed", False)
            accepted = entry.get("human_accepted")
            if status == "passed" and not (passed and (accepted is True or accepted is None)):
                continue
            elif status == "blocked" and passed:
                continue
            elif status == "rejected" and not (passed and accepted is False):
                continue

        ts_ns = entry.get("timestamp_ns", 0)
        ts_sec = ts_ns / 1_000_000_000
        if since_ts and ts_sec < since_ts:
            continue
        if until_ts and ts_sec > until_ts:
            continue

        yield entry


def replay_proposal(entry: Dict[str, Any], config: GateConfig) -> Dict[str, Any]:
    prop_data = entry.get("proposal", {})
    proposal = ActionProposal(
        action_id=prop_data.get("action_id", "unknown"),
        command=prop_data.get("command", ""),
        target_path=prop_data.get("target_path", ""),
        risk_tier=prop_data.get("risk_tier", 1),
    )
    passed, reason, eff_tier = PolicyEngine.evaluate(proposal, config=config)
    return {
        "action_id": proposal.action_id,
        "historical_passed": entry.get("policy_passed"),
        "historical_tier": entry.get("effective_risk_tier"),
        "replay_passed": passed,
        "replay_tier": eff_tier,
        "replay_reason": reason,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Forensic query and replay tool for admission-gate audit logs."
    )
    parser.add_argument(
        "--log-file",
        default="audit_log.jsonl",
        help="Path to audit trail (default: audit_log.jsonl)",
    )
    parser.add_argument("--action-id", help="Filter by exact action_id")
    parser.add_argument("--tier", type=int, choices=[1, 2, 3], help="Filter by risk tier")
    parser.add_argument(
        "--status",
        choices=["passed", "blocked", "rejected"],
        help="Filter by result status: passed (allowed), blocked (policy denied), rejected (operator denied)",
    )
    parser.add_argument("--since", help="Filter actions after time (e.g., '10m', '2h', epoch)")
    parser.add_argument("--until", help="Filter actions before time (e.g., '5m', epoch)")
    parser.add_argument(
        "--replay",
        action="store_true",
        help="Replay matching entries against current active configuration policy",
    )
    parser.add_argument(
        "--config",
        help="Path to TOML configuration file for replay mode",
    )
    args = parser.parse_args()

    since_ts = parse_relative_time(args.since) if args.since else None
    until_ts = parse_relative_time(args.until) if args.until else None

    cfg = None
    if args.replay:
        cfg_file = args.config or find_default_config()
        cfg = GateConfig.load_from_file(cfg_file) if cfg_file else GateConfig()

    matches = 0
    try:
        for entry in filter_entries(
            args.log_file,
            action_id=args.action_id,
            tier=args.tier,
            status=args.status,
            since_ts=since_ts,
            until_ts=until_ts,
        ):
            matches += 1
            if args.replay:
                res = replay_proposal(entry, cfg)
                status_str = "PASS" if res["replay_passed"] else "BLOCK"
                print(f"[{res['action_id']}] Replay {status_str} (Tier {res['replay_tier']}): {res['replay_reason']}")
            else:
                print(json.dumps(entry))
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    if matches == 0:
        sys.exit(0)


if __name__ == "__main__":
    main()
