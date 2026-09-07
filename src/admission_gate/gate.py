#!/usr/bin/env python3
"""
admission_gate.gate - Library interface and execution wrapper for CLI agent actions.
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from typing import List, Optional, Tuple

from admission_gate.config import GateConfig, find_default_config


@dataclass
class ActionProposal:
    action_id: str
    command: str
    target_path: str
    risk_tier: int = 1  # 1 = Low, 2 = Medium, 3 = High


class PolicyEngine:
    DEFAULT_BLOCKED_PATTERNS = ["rm -rf /", ":(){ :|:& };:", "/dev/sd", "> /dev/null"]

    DEFAULT_PROTECTED_PATHS = [
        "/etc",
        "/boot",
        "/sys",
        "/dev",
        "/proc",
        "C:\\Windows",
        "C:\\Windows\\System32",
    ]

    @classmethod
    def _canonicalize(cls, path: str) -> str:
        expanded = os.path.expanduser(path)
        if not os.path.exists(expanded):
            parent = os.path.dirname(expanded) or "."
            real_parent = os.path.realpath(parent)
            norm = os.path.join(real_parent, os.path.basename(expanded))
        else:
            norm = os.path.realpath(expanded)

        norm = os.path.normcase(norm)
        if norm.startswith("\\\\?\\"):
            norm = norm[4:]
        return os.path.abspath(norm)

    @classmethod
    def _is_within(cls, child: str, parent: str) -> bool:
        parent_dir = parent if parent.endswith(os.sep) else parent + os.sep
        return child == parent or child.startswith(parent_dir)

    @classmethod
    def evaluate(
        cls,
        proposal: ActionProposal,
        allowed_roots: Optional[List[str]] = None,
        blocked_patterns: Optional[List[str]] = None,
        protected_paths: Optional[List[str]] = None,
        config: Optional[GateConfig] = None,
    ) -> Tuple[bool, str]:
        # Merge configuration sources
        active_blocked = (
            config.blocked_patterns
            if config
            else (blocked_patterns if blocked_patterns is not None else cls.DEFAULT_BLOCKED_PATTERNS)
        )
        active_protected = (
            config.protected_paths
            if config
            else (protected_paths if protected_paths is not None else cls.DEFAULT_PROTECTED_PATHS)
        )
        active_allowed = (
            allowed_roots
            if allowed_roots is not None
            else (config.allowed_roots if config else None)
        )

        for pattern in active_blocked:
            if pattern in proposal.command:
                return False, f"Blocked: matched hazardous pattern '{pattern}'"

        target_norm = cls._canonicalize(proposal.target_path)

        for raw_protected in active_protected:
            protected_norm = cls._canonicalize(raw_protected)
            if cls._is_within(target_norm, protected_norm):
                return (
                    False,
                    f"Blocked: path resolves to protected directory '{raw_protected}'",
                )

        if active_allowed:
            in_allowed = False
            for raw_allowed in active_allowed:
                allowed_norm = cls._canonicalize(raw_allowed)
                if cls._is_within(target_norm, allowed_norm):
                    in_allowed = True
                    break
            if not in_allowed:
                allowed_str = ", ".join(active_allowed)
                return False, f"Blocked: path escapes allowed roots ({allowed_str})"

        if proposal.risk_tier not in (1, 2, 3):
            return False, "Blocked: invalid risk tier (must be 1, 2, or 3)"

        return True, "Passed automated policy checks."


class AuditLogger:
    def __init__(self, log_path: str = "audit_log.jsonl"):
        self.log_path = log_path
        self.last_hash = self._recover_tip_hash()

    def _recover_tip_hash(self) -> str:
        if not os.path.exists(self.log_path):
            return "0" * 64
        last_line = ""
        with open(self.log_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    last_line = line
        if not last_line:
            return "0" * 64
        try:
            return json.loads(last_line).get("entry_hash", "0" * 64)
        except json.JSONDecodeError:
            return "0" * 64

    def commit(
        self,
        proposal: ActionProposal,
        passed: bool,
        reason: str,
        human_decision: Optional[bool],
    ) -> str:
        payload = {
            "prev_hash": self.last_hash,
            "timestamp_ns": time.time_ns(),
            "proposal": asdict(proposal),
            "policy_passed": passed,
            "policy_reason": reason,
            "human_accepted": human_decision,
        }
        serialized = json.dumps(payload, sort_keys=True)
        entry_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        record = {**payload, "entry_hash": entry_hash}

        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")

        self.last_hash = entry_hash
        return entry_hash


def _prompt_tty(message: str) -> bool:
    try:
        tty_path = "CON:" if os.name == "nt" else "/dev/tty"
        with open(tty_path, "r") as t_in, open(tty_path, "w") as t_out:
            t_out.write(message)
            t_out.flush()
            res = t_in.readline().strip().lower()
            return res in ("y", "yes")
    except (OSError, IOError):
        return False


def evaluate(
    proposal: ActionProposal,
    allowed_roots: Optional[List[str]] = None,
    blocked_patterns: Optional[List[str]] = None,
    protected_paths: Optional[List[str]] = None,
    config: Optional[GateConfig] = None,
) -> Tuple[bool, str]:
    return PolicyEngine.evaluate(
        proposal,
        allowed_roots=allowed_roots,
        blocked_patterns=blocked_patterns,
        protected_paths=protected_paths,
        config=config,
    )


def gated_shell(
    proposal: ActionProposal,
    allowed_roots: Optional[List[str]] = None,
    log_path: Optional[str] = None,
    require_confirm: Optional[bool] = None,
    config: Optional[GateConfig] = None,
) -> Tuple[bool, str, int]:
    cfg = config or GateConfig()
    if allowed_roots is not None:
        cfg.allowed_roots = allowed_roots
    if log_path is not None:
        cfg.log_file = log_path
    if require_confirm is not None:
        cfg.require_confirm = require_confirm

    logger = AuditLogger(log_path=cfg.log_file)
    passed, reason = evaluate(proposal, config=cfg)

    decision = None
    if passed:
        if cfg.require_confirm:
            msg = f"[Agent Gate] Authorize command '{proposal.command}' on target '{proposal.target_path}'? [y/N]: "
            decision = _prompt_tty(msg)
        else:
            decision = True
    else:
        decision = False

    logger.commit(proposal, passed, reason, decision)

    if not (passed and decision):
        err_msg = reason if not passed else "Execution rejected by operator."
        return False, err_msg, -1

    res = subprocess.run(
        proposal.command,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    output = res.stdout if res.returncode == 0 else res.stderr
    return True, output, res.returncode


def main():
    parser = argparse.ArgumentParser(
        description="Deterministic admission gate for CLI agent actions."
    )
    parser.add_argument(
        "--config",
        "-c",
        help="Path to TOML configuration file (default: admission_gate.toml if present)",
    )
    parser.add_argument(
        "--allow-root",
        action="append",
        dest="allowed_roots",
        help="Allowed filesystem boundary (can be specified multiple times)",
    )
    parser.add_argument(
        "--log-file",
        help="Path to write the audit trail (default: audit_log.jsonl)",
    )
    parser.add_argument(
        "--no-confirm",
        action="store_true",
        help="Bypass interactive TTY confirmation (policy checks still enforced)",
    )
    args = parser.parse_args()

    # Load configuration
    config_file = args.config or find_default_config()
    if config_file:
        try:
            config = GateConfig.load_from_file(config_file)
        except Exception as e:
            print(f"[Error loading config] {e}", file=sys.stderr)
            sys.exit(2)
    else:
        config = GateConfig()

    # Command-line arguments override configuration file values
    if args.allowed_roots:
        config.allowed_roots = args.allowed_roots
    if args.log_file:
        config.log_file = args.log_file
    if args.no_confirm:
        config.require_confirm = False

    logger = AuditLogger(log_path=config.log_file)
    print(f"[Agent Gate] Online. Log: {config.log_file} (Tip: {logger.last_hash[:16]}...)")
    if config.allowed_roots:
        print(f"[Policy] Sandboxed roots: {', '.join(config.allowed_roots)}")

    if not sys.stdin.isatty():
        for line in sys.stdin:
            raw = line.strip()
            if not raw:
                continue
            try:
                data = json.loads(raw)
                proposal = ActionProposal(
                    action_id=str(data["action_id"]),
                    command=str(data["command"]),
                    target_path=str(data["target_path"]),
                    risk_tier=int(data.get("risk_tier", 1)),
                )
                executed, out, code = gated_shell(proposal, config=config)
                status = f"Code {code}" if executed else "Blocked"
                print(f"Result [{proposal.action_id}]: {status} - {out.strip()}")
            except Exception as e:
                print(f"Error parsing line: {e}", file=sys.stderr)
    else:
        print("Reading stdin for JSON proposals. Example:")
        print('{"action_id": "1", "command": "echo test", "target_path": "./workspace", "risk_tier": 1}')


if __name__ == "__main__":
    main()
