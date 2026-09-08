"""
admission_gate - Deterministic admission control and cryptographic audit logging for CLI agents.
"""

from admission_gate.config import ExecConfig, GateConfig, ProcessConfig, RateLimitConfig
from admission_gate.gate import (
    ActionProposal,
    AuditLogger,
    PolicyEngine,
    RateLimiter,
    evaluate,
    gated_shell,
)
from admission_gate.query import filter_entries, replay_proposal
from admission_gate.verify import verify_log

__all__ = [
    "ActionProposal",
    "AuditLogger",
    "ExecConfig",
    "GateConfig",
    "ProcessConfig",
    "PolicyEngine",
    "RateLimitConfig",
    "RateLimiter",
    "evaluate",
    "filter_entries",
    "gated_shell",
    "replay_proposal",
    "verify_log",
]
__version__ = "0.3.0"
