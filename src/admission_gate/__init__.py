"""
admission_gate - Deterministic admission control and cryptographic audit logging for CLI agents.
"""

from admission_gate.config import GateConfig
from admission_gate.gate import (
    ActionProposal,
    AuditLogger,
    PolicyEngine,
    evaluate,
    gated_shell,
)
from admission_gate.verify import verify_log

__all__ = [
    "ActionProposal",
    "AuditLogger",
    "GateConfig",
    "PolicyEngine",
    "evaluate",
    "gated_shell",
    "verify_log",
]
__version__ = "0.1.1"
