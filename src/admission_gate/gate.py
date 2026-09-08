#!/usr/bin/env python3
"""
admission_gate.gate - Library interface and execution wrapper for CLI agent actions.
"""

import argparse
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import time
from collections import deque
from dataclasses import asdict, dataclass
from typing import Deque, List, Optional, Set, Tuple

import shutil
from admission_gate.config import (
    DEFAULT_ALLOWED_BINARIES,
    DEFAULT_DENIED_BINARIES,
    ExecConfig,
    GateConfig,
    RateLimitConfig,
    find_default_config,
)


@dataclass
class ActionProposal:
    action_id: str
    command: str
    target_path: str
    risk_tier: int = 1  # 1 = Low, 2 = Medium, 3 = High


class RateLimiter:
    """Zero-dependency in-memory sliding-window rate limiter and burst controller."""

    def __init__(self, config: Optional[RateLimitConfig] = None):
        self.config = config or RateLimitConfig()
        self.history: Deque[float] = deque()
        self.last_tier3_time: float = 0.0

    def check(self, risk_tier: int) -> Tuple[bool, bool, str]:
        """
        Evaluates current request rate against window thresholds.
        Returns:
            (is_allowed: bool, force_confirm: bool, reason: str)
        """
        if not self.config.enabled:
            return True, False, "Rate limiting disabled."

        now = time.monotonic()

        # Enforce Tier 3 cooldown
        cooldown_rem = (self.last_tier3_time + self.config.tier3_cooldown_seconds) - now
        if cooldown_rem > 0:
            return (
                False,
                False,
                f"Rate limit: Tier 3 cooldown active ({cooldown_rem:.1f}s remaining)",
            )

        # Evict timestamps outside sliding window (60 seconds)
        window = 60.0
        while self.history and self.history[0] <= now - window:
            self.history.popleft()

        # Hard velocity limit check
        if len(self.history) >= self.config.max_requests_per_minute:
            return (
                False,
                False,
                f"Rate limit exceeded: {len(self.history)} actions in {window:.0f}s "
                f"(max {self.config.max_requests_per_minute})",
            )

        # Burst check: force human confirmation on sudden velocity spike
        recent_10s = sum(1 for t in self.history if t > now - 10.0)
        force_confirm = recent_10s >= self.config.burst_threshold

        return True, force_confirm, "Rate check passed."

    def record(self, risk_tier: int):
        if not self.config.enabled:
            return
        now = time.monotonic()
        self.history.append(now)
        if risk_tier >= 3:
            self.last_tier3_time = now


# Shared process-level rate limiter instance
_DEFAULT_LIMITER = RateLimiter()


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

    SUBSHELL_PATTERNS = [
        r"\$\(.*\)",     # $(cmd)
        r"`.*`",         # `cmd`
        r"<\(.*\)",     # <(cmd)
        r">\([^\)]*\)",  # >(cmd)
    ]

    ENV_VAR_PATTERNS = [
        r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?",  # $VAR or ${VAR}
        r"%[A-Za-z_][A-Za-z0-9_]*%",        # %VAR% (Windows)
    ]

    TIER_3_COMMANDS = {
        "rm", "mv", "chmod", "chown", "dd", "truncate",
        "kill", "pkill", "systemctl", "mkfs", "fdisk", "shred"
    }

    TIER_1_COMMANDS = {
        "cat", "head", "tail", "less", "more", "grep", "egrep", "fgrep",
        "ls", "pwd", "which", "whereis", "find", "stat", "file",
        "wc", "diff", "echo", "printf", "true", "false", "test"
    }

    MULTIPLEXER_BINARIES = {"coreutils", "busybox", "toybox"}

    @classmethod
    def resolve_binary(cls, binary_token: str) -> Tuple[Optional[str], str, str]:
        invoked_base = os.path.basename(binary_token)
        if os.sep in binary_token or (os.altsep and os.altsep in binary_token) or binary_token.startswith("."):
            real = cls._canonicalize(binary_token)
            return real, invoked_base, os.path.basename(real)
        found = shutil.which(binary_token)
        if found:
            real = cls._canonicalize(found)
            return real, invoked_base, os.path.basename(real)
        return None, invoked_base, invoked_base

    @classmethod
    def verify_executables(cls, command: str, exec_config: ExecConfig) -> Tuple[bool, str, List[str]]:
        segments = re.split(r"[;&|]+", command)
        resolved_binaries = []
        allow_set = set(exec_config.allow) if exec_config.allow else set(DEFAULT_ALLOWED_BINARIES)
        deny_set = set(exec_config.deny) if exec_config.deny is not None else set(DEFAULT_DENIED_BINARIES)

        for segment in segments:
            seg = segment.strip()
            if not seg:
                continue
            try:
                tokens = shlex.split(seg, posix=os.name != "nt")
            except ValueError:
                return False, "Malformed command tokenization", []
            if not tokens:
                continue
            raw_argv0 = tokens[0]
            real_path, invoked_base, real_base = cls.resolve_binary(raw_argv0)
            resolved_binaries.append(real_path or invoked_base)

            for candidate in (invoked_base, real_base, real_path):
                if candidate and candidate in deny_set:
                    return False, f"Blocked: binary '{candidate}' is explicitly denied by execution policy", resolved_binaries

            is_allowed = False
            candidates_to_check = {invoked_base}
            if real_base not in cls.MULTIPLEXER_BINARIES:
                candidates_to_check.add(real_base)
                if real_path:
                    candidates_to_check.add(real_path)

            for cand in candidates_to_check:
                if cand in allow_set:
                    is_allowed = True
                    break
                for allowed in allow_set:
                    if cand.startswith(allowed) and any(c.isdigit() for c in cand[len(allowed):]):
                        is_allowed = True
                        break
                if is_allowed:
                    break

            if not is_allowed:
                display_name = invoked_base if invoked_base == real_base else f"{invoked_base} -> {real_base}"
                res_disp = real_path or "unresolved"
                return False, f"Blocked: binary '{display_name}' ({res_disp}) is not in execution allowlist", resolved_binaries

        return True, "All binaries verified.", resolved_binaries

    @classmethod
    def classify_risk(cls, command: str) -> Tuple[int, str]:
        segments = re.split(r"[;&|]+", command)
        max_tier = 1
        reasons = []

        if re.search(r"(?:^|[^<])>{1,2}", command):
            max_tier = max(max_tier, 2)
            reasons.append("output redirection detected")

        for segment in segments:
            seg = segment.strip()
            if not seg:
                continue

            try:
                tokens = shlex.split(seg, posix=os.name != "nt")
            except ValueError:
                return 3, "malformed command quotes/syntax"

            if not tokens:
                continue

            binary = os.path.basename(tokens[0])

            if binary == "sed" and any(arg.startswith("-i") or arg == "--in-place" for arg in tokens[1:]):
                max_tier = max(max_tier, 3)
                reasons.append("sed in-place edit (-i)")
                continue

            if binary in cls.TIER_3_COMMANDS:
                max_tier = max(max_tier, 3)
                reasons.append(f"destructive binary '{binary}'")
            elif binary in cls.TIER_1_COMMANDS:
                pass
            else:
                max_tier = max(max_tier, 2)
                reasons.append(f"mutating or unclassified binary '{binary}'")

        if not reasons:
            reasons.append("read-only binary match")

        return max_tier, "; ".join(reasons)

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
    def _extract_command_paths(cls, command: str) -> Set[str]:
        paths = set()
        try:
            tokens = shlex.split(command, posix=os.name != "nt")
        except ValueError:
            return paths

        path_prefixes = ("/", "./", "../", "~", "$", "%")
        # argv[0] is governed by exec_policy, not path confinement
        operand_tokens = tokens[1:] if len(tokens) > 1 else []
        for idx, token in enumerate(operand_tokens):
            if token in (">", ">>", "<") and idx + 1 < len(tokens):
                paths.add(tokens[idx + 1])
                continue

            clean_token = token
            if clean_token.startswith(">>"):
                clean_token = clean_token[2:]
            elif clean_token.startswith(">") or clean_token.startswith("<"):
                clean_token = clean_token[1:]

            # Skip URLs
            if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", clean_token):
                continue

            if (
                clean_token.startswith(path_prefixes)
                or (len(clean_token) > 2 and clean_token[1:3] == ":\\")
                or "/" in clean_token
                or "\\" in clean_token
                or "$" in clean_token
                or "%" in clean_token
            ):
                paths.add(clean_token)

        return paths

    @classmethod
    def evaluate(
        cls,
        proposal: ActionProposal,
        allowed_roots: Optional[List[str]] = None,
        blocked_patterns: Optional[List[str]] = None,
        protected_paths: Optional[List[str]] = None,
        config: Optional[GateConfig] = None,
        read_roots: Optional[List[str]] = None,
        write_roots: Optional[List[str]] = None,
    ) -> Tuple[bool, str, int]:
        active_config = config or GateConfig()
        if allowed_roots is not None:
            active_config.allowed_roots = allowed_roots
        if read_roots is not None:
            active_config.read_roots = read_roots
        if write_roots is not None:
            active_config.write_roots = write_roots
        if blocked_patterns is not None:
            active_config.blocked_patterns = blocked_patterns
        if protected_paths is not None:
            active_config.protected_paths = protected_paths

        # Determine effective roots (fall back to legacy allowed_roots if not configured)
        effective_read = list(active_config.read_roots)
        effective_write = list(active_config.write_roots)
        if not effective_read and not effective_write and active_config.allowed_roots:
            effective_read = list(active_config.allowed_roots)
            effective_write = list(active_config.allowed_roots)

        inferred_tier, _ = cls.classify_risk(proposal.command)
        effective_tier = max(proposal.risk_tier, inferred_tier)

        # 1. Blocked Pattern Checks
        for pattern in active_config.blocked_patterns:
            if pattern in proposal.command:
                return False, f"Blocked: matched hazardous pattern '{pattern}'", effective_tier

        # 2. Metacharacter & Subshell Substitution Checks
        for sub_pat in cls.SUBSHELL_PATTERNS:
            if re.search(sub_pat, proposal.command):
                return False, f"Blocked: metacharacter or subshell substitution detected matching '{sub_pat}'", effective_tier

        # 3. Environment Variable Evasion Checks
        paths_to_check = {proposal.target_path} | cls._extract_command_paths(proposal.command)
        for raw_path in paths_to_check:
            for var_pat in cls.ENV_VAR_PATTERNS:
                if re.search(var_pat, raw_path):
                    return (
                        False,
                        f"Blocked: unexpanded environment variable detected in path '{raw_path}'",
                        effective_tier,
                    )

        # 4. Executable Allowlist / Denylist Check
        exec_ok, exec_reason, _ = cls.verify_executables(
            proposal.command, active_config.exec_policy
        )
        if not exec_ok:
            return False, exec_reason, effective_tier

        # 5. Path Jail & Protected Paths Checks
        for raw_path in paths_to_check:
            norm_path = cls._canonicalize(raw_path)

            for raw_protected in active_config.protected_paths:
                protected_norm = cls._canonicalize(raw_protected)
                if cls._is_within(norm_path, protected_norm):
                    return (
                        False,
                        f"Blocked: path '{raw_path}' resolves to protected directory '{raw_protected}'",
                        effective_tier,
                    )

            # Split Root Confinement
            if effective_read or effective_write:
                if effective_tier == 1:
                    # Tier 1 reads are permitted in read_roots UNION write_roots
                    allowed_pool = effective_read + [w for w in effective_write if w not in effective_read]
                    in_pool = any(cls._is_within(norm_path, cls._canonicalize(r)) for r in allowed_pool)
                    if not in_pool:
                        pool_str = ", ".join(allowed_pool)
                        if active_config.allowed_roots and not active_config.read_roots and not active_config.write_roots:
                            err = f"Blocked: path '{raw_path}' escapes allowed roots ({pool_str})"
                        else:
                            err = f"Blocked: path '{raw_path}' escapes read boundaries ({pool_str})"
                        return False, err, effective_tier
                else:
                    # Tier 2/3 mutations require strictly write_roots
                    if effective_write:
                        in_write = any(cls._is_within(norm_path, cls._canonicalize(w)) for w in effective_write)
                        if not in_write:
                            # Check if it was in read_roots for clearer error reporting
                            in_read = any(cls._is_within(norm_path, cls._canonicalize(r)) for r in effective_read)
                            if in_read:
                                return (
                                    False,
                                    f"Blocked: mutating/destructive action targets read-only root '{raw_path}'",
                                    effective_tier,
                                )
                            write_str = ", ".join(effective_write)
                            if active_config.allowed_roots and not active_config.read_roots and not active_config.write_roots:
                                err = f"Blocked: path '{raw_path}' escapes allowed roots ({write_str})"
                            else:
                                err = f"Blocked: path '{raw_path}' escapes write_roots ({write_str})"
                            return False, err, effective_tier

        if proposal.risk_tier not in (1, 2, 3):
            return False, "Blocked: invalid risk tier (must be 1, 2, or 3)", effective_tier

        return True, "Passed automated policy checks.", effective_tier


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
        effective_tier: int = 1,
    ) -> str:
        payload = {
            "prev_hash": self.last_hash,
            "timestamp_ns": time.time_ns(),
            "proposal": asdict(proposal),
            "effective_risk_tier": effective_tier,
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
    passed, reason, _ = PolicyEngine.evaluate(
        proposal,
        allowed_roots=allowed_roots,
        blocked_patterns=blocked_patterns,
        protected_paths=protected_paths,
        config=config,
    )
    return passed, reason


def gated_shell(
    proposal: ActionProposal,
    allowed_roots: Optional[List[str]] = None,
    read_roots: Optional[List[str]] = None,
    write_roots: Optional[List[str]] = None,
    log_path: Optional[str] = None,
    require_confirm: Optional[bool] = None,
    config: Optional[GateConfig] = None,
    verify_only: bool = False,
    limiter: Optional[RateLimiter] = None,
) -> Tuple[bool, str, int]:
    cfg = config or GateConfig()
    if allowed_roots is not None:
        cfg.allowed_roots = allowed_roots
    if read_roots is not None:
        cfg.read_roots = read_roots
    if write_roots is not None:
        cfg.write_roots = write_roots
    if log_path is not None:
        cfg.log_file = log_path
    if require_confirm is not None:
        cfg.require_confirm = require_confirm

    active_limiter = limiter or _DEFAULT_LIMITER
    active_limiter.config = cfg.rate_limit

    logger = AuditLogger(log_path=cfg.log_file)
    passed, reason, effective_tier = PolicyEngine.evaluate(proposal, config=cfg)
    _, _, resolved_bins = PolicyEngine.verify_executables(proposal.command, cfg.exec_policy)

    # Apply rate limiting & burst checks if policy passed
    rate_ok, force_confirm, rate_reason = active_limiter.check(effective_tier)
    if not rate_ok:
        passed = False
        reason = rate_reason

    if verify_only:
        logger.commit(proposal, passed, reason, human_decision=None, effective_tier=effective_tier)
        return passed, reason, 0 if passed else -1

    decision = None
    if passed:
        needs_confirm = cfg.require_confirm or force_confirm
        if needs_confirm:
            spike_warn = " [BURST ESCALATION]" if force_confirm and not cfg.require_confirm else ""
            msg = (
                f"[Agent Gate]{spike_warn} Authorize [Tier {effective_tier}] command '{proposal.command}' "
                f"on target '{proposal.target_path}'? [y/N]: "
            )
            decision = _prompt_tty(msg)
        else:
            decision = True
    else:
        decision = False

    logger.commit(proposal, passed, reason, decision, effective_tier=effective_tier)

    if not (passed and decision):
        err_msg = reason if not passed else "Execution rejected by operator."
        return False, err_msg, -1

    # Record successful admission in rate-limiter state
    active_limiter.record(effective_tier)

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
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="Evaluate and audit proposal without executing command or prompting TTY",
    )
    args = parser.parse_args()

    config_file = args.config or find_default_config()
    if config_file:
        try:
            config = GateConfig.load_from_file(config_file)
        except Exception as e:
            print(f"[Error loading config] {e}", file=sys.stderr)
            sys.exit(2)
    else:
        config = GateConfig()

    if args.allowed_roots:
        config.allowed_roots = args.allowed_roots
    if args.log_file:
        config.log_file = args.log_file
    if args.no_confirm:
        config.require_confirm = False

    logger = AuditLogger(log_path=config.log_file)
    mode_desc = "Verify-Only" if args.verify_only else "Active Gate"
    print(f"[Agent Gate] Online ({mode_desc}). Log: {config.log_file} (Tip: {logger.last_hash[:16]}...)")
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
                executed, out, code = gated_shell(
                    proposal, config=config, verify_only=args.verify_only
                )
                status = f"Code {code}" if executed else "Blocked"
                print(f"Result [{proposal.action_id}]: {status} - {out.strip()}")
            except Exception as e:
                print(f"Error parsing line: {e}", file=sys.stderr)
    else:
        print("Reading stdin for JSON proposals. Example:")
        print('{"action_id": "1", "command": "echo test", "target_path": "./workspace", "risk_tier": 1}')


if __name__ == "__main__":
    main()
