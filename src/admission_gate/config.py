"""
admission_gate.config - Zero-dependency configuration loader for admission-gate.
Supports TOML format using standard library tomllib (Python 3.11+) or minimal fallback.
"""

import os
import sys
from dataclasses import dataclass, field
from typing import List, Optional

try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib  # type: ignore
    except ImportError:
        tomllib = None



DEFAULT_ALLOWED_BINARIES = [
    "git", "python", "python3", "pytest", "ls", "cat", "head",
    "tail", "grep", "diff", "echo", "pwd", "which", "find", "stat",
    "wc", "rm", "mv", "cp", "touch", "mkdir", "true", "type", "file"
]

DEFAULT_DENIED_BINARIES = [
    "curl", "wget", "nc", "netcat", "ssh", "scp", "sftp", "nmap",
    "socat", "telnet", "ftp", "rsync"
]


@dataclass
class ExecConfig:
    allow: List[str] = field(default_factory=lambda: list(DEFAULT_ALLOWED_BINARIES))
    deny: List[str] = field(default_factory=lambda: list(DEFAULT_DENIED_BINARIES))

@dataclass
class RateLimitConfig:
    enabled: bool = True
    max_requests_per_minute: int = 30
    burst_threshold: int = 10  # Velocity spike forcing confirmation
    tier3_cooldown_seconds: float = 3.0  # Quiescent period after Tier 3 commands


@dataclass
class GateConfig:
    blocked_patterns: List[str] = field(
        default_factory=lambda: [
            "rm -rf /",
            ":(){ :|:& };:",
            "/dev/sd",
            "> /dev/null",
        ]
    )
    protected_paths: List[str] = field(
        default_factory=lambda: [
            "/etc",
            "/boot",
            "/sys",
            "/dev",
            "/proc",
            "C:\\Windows",
            "C:\\Windows\\System32",
        ]
    )
    allowed_roots: List[str] = field(default_factory=list)
    read_roots: List[str] = field(default_factory=list)
    write_roots: List[str] = field(default_factory=list)
    log_file: str = "audit_log.jsonl"
    require_confirm: bool = True
    rate_limit: RateLimitConfig = field(default_factory=RateLimitConfig)
    exec_policy: ExecConfig = field(default_factory=ExecConfig)

    @classmethod
    def load_from_file(cls, path: str) -> "GateConfig":
        if not os.path.exists(path):
            raise FileNotFoundError(f"Config file not found: {path}")

        cfg = cls()

        if tomllib is not None:
            with open(path, "rb") as f:
                data = tomllib.load(f)
        else:
            data = _parse_simple_toml(path)

        policy = data.get("policy", {})
        if "blocked_patterns" in policy:
            cfg.blocked_patterns = list(policy["blocked_patterns"])
        if "require_confirm" in policy:
            cfg.require_confirm = bool(policy["require_confirm"])

        fs = data.get("filesystem", {})
        if "protected_paths" in fs:
            cfg.protected_paths = list(fs["protected_paths"])
        if "allowed_roots" in fs:
            cfg.allowed_roots = list(fs["allowed_roots"])
        if "read_roots" in fs:
            cfg.read_roots = list(fs["read_roots"])
        if "write_roots" in fs:
            cfg.write_roots = list(fs["write_roots"])

        # Backward-compatibility fallback
        if cfg.allowed_roots and not cfg.read_roots and not cfg.write_roots:
            cfg.read_roots = list(cfg.allowed_roots)
            cfg.write_roots = list(cfg.allowed_roots)

        logging = data.get("logging", {})
        if "log_file" in logging:
            cfg.log_file = str(logging["log_file"])

        rl = data.get("rate_limit", {})
        if "enabled" in rl:
            cfg.rate_limit.enabled = bool(rl["enabled"])
        if "max_requests_per_minute" in rl:
            cfg.rate_limit.max_requests_per_minute = int(rl["max_requests_per_minute"])
        if "burst_threshold" in rl:
            cfg.rate_limit.burst_threshold = int(rl["burst_threshold"])
        if "tier3_cooldown_seconds" in rl:
            cfg.rate_limit.tier3_cooldown_seconds = float(rl["tier3_cooldown_seconds"])

        ep = data.get("exec", {})
        if "allow" in ep:
            cfg.exec_policy.allow = list(ep["allow"])
        if "deny" in ep:
            cfg.exec_policy.deny = list(ep["deny"])

        return cfg


def _parse_simple_toml(path: str) -> dict:
    """Fallback basic TOML reader when tomllib is absent."""
    result = {}
    current_section = result

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("[") and line.endswith("]"):
                section_name = line[1:-1].strip()
                result[section_name] = {}
                current_section = result[section_name]
            elif "=" in line:
                key, val = line.split("=", 1)
                key = key.strip()
                val = val.strip()
                if val.startswith("[") and val.endswith("]"):
                    raw_items = val[1:-1].split(",")
                    items = [
                        i.strip().strip("\"'")
                        for i in raw_items
                        if i.strip().strip("\"'")
                    ]
                    current_section[key] = items
                elif val.lower() in ("true", "false"):
                    current_section[key] = val.lower() == "true"
                elif val.replace(".", "", 1).isdigit():
                    current_section[key] = float(val) if "." in val else int(val)
                else:
                    current_section[key] = val.strip("\"'")
    return result


def find_default_config() -> Optional[str]:
    cur = os.getcwd()
    candidate = os.path.join(cur, "admission_gate.toml")
    if os.path.isfile(candidate):
        return candidate
    return None
