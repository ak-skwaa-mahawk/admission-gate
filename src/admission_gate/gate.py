#!/usr/bin/env python3
"""
admission_gate.gate - Library interface and execution wrapper for CLI agent actions.
"""

import hashlib
import json
import os
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from typing import List, Optional, Tuple


@dataclass
class ActionProposal:
    action_id: str
    command: str
    target_path: str
    risk_tier: int = 1  # 1 = Low, 2 = Medium, 3 = High


class PolicyEngine:
    BLOCKED_PATTERNS = ["rm -rf /", ":(){ :|:& };:", "/dev/sd", "> /dev/null"]

    PROTECTED_PATHS = [
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
    ) -> Tuple[bool, str]:
        for pattern in cls.BLOCKED_PATTERNS:
            if pattern in proposal.command:
                return False, f"Blocked: matched hazardous pattern '{pattern}'"

        target_norm = cls._canonicalize(proposal.target_path)

        for raw_protected in cls.PROTECTED_PATHS:
            protected_norm = cls._canonicalize(raw_protected)
            if cls._is_within(target_norm, protected_norm):
                return (
                    False,
                    f"Blocked: path resolves to protected directory '{raw_protected}'",
                )

        if allowed_roots:
            in_allowed = False
            for raw_allowed in allowed_roots:
                allowed_norm = cls._canonicalize(raw_allowed)
                if cls._is_within(target_norm, allowed_norm):
                    in_allowed = True
                    break
            if not in_allowed:
                allowed_str = ", ".join(allowed_roots)
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
    proposal: ActionProposal, allowed_roots: Optional[List[str]] = None
) -> Tuple[bool, str]:
    return PolicyEngine.evaluate(proposal, allowed_roots=allowed_roots)


def gated_shell(
    proposal: ActionProposal,
    allowed_roots: Optional[List[str]] = None,
    log_path: str = "audit_log.jsonl",
    require_confirm: bool = True,
) -> Tuple[bool, str, int]:
    logger = AuditLogger(log_path=log_path)
    passed, reason = evaluate(proposal, allowed_roots=allowed_roots)

    decision = None
    if passed:
        if require_confirm:
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
    logger = AuditLogger()
    print(f"[Agent Gate] Online. Tip hash: {logger.last_hash[:16]}...")

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
                executed, out, code = gated_shell(proposal)
                status = f"Code {code}" if executed else "Blocked"
                print(f"Result [{proposal.action_id}]: {status} - {out.strip()}")
            except Exception as e:
                print(f"Error parsing line: {e}", file=sys.stderr)
    else:
        print("Listening on stdin for JSON proposals. Example:")
        print('{"action_id": "1", "command": "echo test", "target_path": "./workspace", "risk_tier": 1}')


if __name__ == "__main__":
    main()
